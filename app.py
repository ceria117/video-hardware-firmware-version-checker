
import sqlite3
import datetime
import json
import re
import html as html_lib
from pathlib import Path
from urllib import request, parse
from urllib.error import URLError, HTTPError
import ssl
import pandas as pd
from typing import Optional, List, Dict
import gradio as gr

DEFAULT_DB_PATH = "firmware_tracker.sqlite3"
TEST_DB_PATH = "test_firmware_tracker.sqlite3"
CURRENT_DB_PATH = DEFAULT_DB_PATH
MAX_LOGS = 500
LOG_BUFFER: List[dict] = []


# -------------------------
# DB helpers
# -------------------------
def db():
    conn = sqlite3.connect(CURRENT_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def set_db_path(path: str) -> None:
    global CURRENT_DB_PATH
    CURRENT_DB_PATH = path
    log_warn(f"Database switched to: {CURRENT_DB_PATH}")


def init_db():
    try:
        conn = db()
        cur = conn.cursor()

        cur.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT NOT NULL,
        vendor TEXT NOT NULL,
        model TEXT NOT NULL,
        installed_version TEXT NOT NULL,
        previous_installed_version TEXT,
        nickname TEXT,
        notes TEXT,
        created_at TEXT NOT NULL
    )
    """)

        cur.execute("""
    CREATE TABLE IF NOT EXISTS catalog (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vendor TEXT NOT NULL,
        model TEXT NOT NULL,
        latest_version TEXT NOT NULL,
        url TEXT,
        release_date TEXT,
        notes TEXT,
        updated_at TEXT NOT NULL,
        UNIQUE(vendor, model)
    )
    """)

        cols = [r[1] for r in cur.execute("PRAGMA table_info(devices)").fetchall()]
        if "previous_installed_version" not in cols:
            cur.execute("ALTER TABLE devices ADD COLUMN previous_installed_version TEXT")

        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        log_error(f"DB init failed: {e}")


# -------------------------
# CRUD: Devices
# -------------------------
def format_display_datetime(value: Optional[str]) -> str:
    if not value:
        return ""
    try:
        dt = datetime.datetime.fromisoformat(value)
    except ValueError:
        return value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    local_dt = dt.astimezone()
    return local_dt.strftime("%m/%d/%Y %I:%M:%S%p")

def add_device(category, vendor, model, installed_version, nickname, notes):
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO devices (category, vendor, model, installed_version, previous_installed_version, nickname, notes, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        category.strip(),
        vendor.strip(),
        model.strip(),
        installed_version.strip(),
        None,
        (nickname or "").strip(),
        (notes or "").strip(),
        datetime.datetime.now(datetime.timezone.utc).isoformat()
    ))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        log_error(f"Add device failed: {e}")


def list_devices() -> List[dict]:
    try:
        conn = db()
        rows = conn.execute("SELECT * FROM devices ORDER BY vendor, model, nickname").fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except sqlite3.Error as e:
        log_error(f"List devices failed: {e}")
        return []

def update_device(device_id: int, category: str, vendor: str, model: str, installed_version: str, nickname: str, notes: str):
    try:
        conn = db()
        cur = conn.cursor()
        row = cur.execute("SELECT installed_version, previous_installed_version FROM devices WHERE id = ?", (int(device_id),)).fetchone()
        prev_installed = row["previous_installed_version"] if row else None
        current_installed = row["installed_version"] if row else None
        new_installed = installed_version.strip()
        if current_installed and new_installed != current_installed:
            prev_installed = current_installed
        cur.execute("""
        UPDATE devices
        SET category = ?, vendor = ?, model = ?, installed_version = ?, previous_installed_version = ?, nickname = ?, notes = ?
        WHERE id = ?
    """, (
        category.strip(),
        vendor.strip(),
        model.strip(),
        new_installed,
        prev_installed,
        (nickname or "").strip(),
        (notes or "").strip(),
        int(device_id),
    ))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        log_error(f"Update device failed: {e}")


def delete_device(device_id: int):
    try:
        conn = db()
        conn.execute("DELETE FROM devices WHERE id = ?", (int(device_id),))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        log_error(f"Delete device failed: {e}")


# -------------------------
# CRUD: Manual Catalog
# -------------------------
def upsert_catalog(vendor, model, latest_version, url, release_date, notes):
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO catalog (vendor, model, latest_version, url, release_date, notes, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(vendor, model) DO UPDATE SET
            latest_version=excluded.latest_version,
            url=excluded.url,
            release_date=excluded.release_date,
            notes=excluded.notes,
            updated_at=excluded.updated_at
    """, (
        vendor.strip(),
        model.strip(),
        latest_version.strip(),
        (url or "").strip(),
        (release_date or "").strip(),
        (notes or "").strip(),
        datetime.datetime.now(datetime.timezone.utc).isoformat()
    ))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        log_error(f"Upsert catalog failed: {e}")


def list_catalog() -> List[dict]:
    try:
        conn = db()
        rows = conn.execute("SELECT * FROM catalog ORDER BY vendor, model").fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except sqlite3.Error as e:
        log_error(f"List catalog failed: {e}")
        return []


def delete_catalog_row(row_id: int):
    try:
        conn = db()
        conn.execute("DELETE FROM catalog WHERE id = ?", (int(row_id),))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        log_error(f"Delete catalog row failed: {e}")


def get_catalog_entry(vendor: str, model: str) -> Optional[dict]:
    try:
        conn = db()
        row = conn.execute("""
        SELECT * FROM catalog WHERE vendor = ? AND model = ?
    """, (vendor, model)).fetchone()
        conn.close()
        return dict(row) if row else None
    except sqlite3.Error as e:
        log_error(f"Get catalog entry failed: {e}")
        return None


# -------------------------
# Version compare (simple v1)
# -------------------------
def compare_versions(installed: str, latest: Optional[str]) -> str:
    if not latest:
        return "Unknown"
    if installed.strip() == latest.strip():
        return "Up to date"
    return "Update available"

def status_code(status: str, last_checked: str, has_latest: bool) -> str:
    if status == "Up to date":
        return "up_to_date"
    if status == "Update available":
        if last_checked == "Never":
            return "unknown"
        return "update_available"
    if not has_latest and last_checked != "Never":
        return "warning_no_version"
    return "unknown"

def format_status(code: str, last_checked: str) -> str:
    if code == "up_to_date":
        return "✅ Up to date"
    if code == "update_available":
        return "🟥 Update available"
    if code == "warning_no_version":
        return "⚠️ Unknown (no version)"
    if last_checked == "Never":
        return "⚠️ Unknown (never checked)"
    return "⚠️ Unknown"


PROVIDER_CATALOG_PATH = Path(__file__).with_name("provider_catalog.json")
MODEL_OPTIONS_PATH = Path(__file__).with_name("model_options.json")
VENDORS_PATH = Path(__file__).with_name("vendors.json")
CATEGORIES_PATH = Path(__file__).with_name("categories.json")
ROLAND_PAGES_PATH = Path(__file__).with_name("roland_pages.json")
PANASONIC_PAGES_PATH = Path(__file__).with_name("panasonic_pages.json")
BLACKMAGIC_DOWNLOADS_URL = "https://www.blackmagicdesign.com/api/support/nz/downloads.json"
DECIMATOR_DOWNLOADS_URL = "https://decimator.com/DOWNLOADS/DOWNLOADS.html"
ROLAND_DEBUG_DIR = Path(__file__).with_name("debug_roland")
DECIMATOR_DEBUG_DIR = Path(__file__).with_name("debug_decimator")
PANASONIC_DEBUG_DIR = Path(__file__).with_name("debug_panasonic")
FETCH_CACHE_PATH = Path(__file__).with_name("fetch_cache.json")
CACHE_TTL_SECONDS = 60 * 60  # 1 hour

def load_provider_catalog() -> Dict[str, Dict[str, Dict[str, str]]]:
    if not PROVIDER_CATALOG_PATH.exists():
        log_warn(f"Provider catalog missing: {PROVIDER_CATALOG_PATH}")
        return {}
    try:
        with PROVIDER_CATALOG_PATH.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        log_error(f"Failed to load provider catalog: {e}")
        return {}

def save_provider_catalog(data: Dict) -> None:
    try:
        with PROVIDER_CATALOG_PATH.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
    except OSError as e:
        log_error(f"Failed to save provider catalog: {e}")

def fetch_json(url: str, timeout: int = 15) -> Optional[dict]:
    try:
        req = request.Request(url, headers={"User-Agent": "FirmwareChecker/1.0"})
        with request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (URLError, HTTPError, json.JSONDecodeError) as e:
        log_warn(f"Fetch JSON failed: {url} ({e})")
        return None

def log_warn(msg: str) -> None:
    add_log("WARN", msg)

def log_error(msg: str) -> None:
    add_log("ERROR", msg)

def add_log(level: str, msg: str) -> None:
    ts = datetime.datetime.now().strftime("%m/%d/%Y %I:%M:%S%p")
    LOG_BUFFER.append({"time": ts, "level": level, "message": msg})
    if len(LOG_BUFFER) > MAX_LOGS:
        del LOG_BUFFER[:len(LOG_BUFFER) - MAX_LOGS]
    print(f"[{level}] {msg}")

def fetch_text(url: str, timeout: int = 15, verify_ssl: bool = True) -> Optional[str]:
    try:
        req = request.Request(url, headers={"User-Agent": "FirmwareChecker/1.0"})
        context = None
        if not verify_ssl:
            context = ssl._create_unverified_context()
            log_warn(f"SSL verification disabled for: {url}")
        with request.urlopen(req, timeout=timeout, context=context) as resp:
            raw = resp.read()
            charset = None
            if resp.headers.get_content_charset():
                charset = resp.headers.get_content_charset()
            if not charset:
                head = raw[:4096].decode("ascii", errors="ignore")
                m = re.search(r"charset=([A-Za-z0-9_\\-]+)", head, flags=re.IGNORECASE)
                if m:
                    charset = m.group(1)
            if not charset:
                charset = "utf-8"
            return raw.decode(charset, errors="replace")
    except (URLError, HTTPError) as e:
        log_warn(f"Fetch text failed: {url} ({e})")
        return None

def normalize_version(major: int, minor: int, release_num: int, build_num: int) -> str:
    base = f"{major}.{minor}"
    if release_num and release_num > 0:
        return f"{base}.{release_num}"
    return base

def blackmagic_product_for_model(model: str, product_keys: List[str]) -> Optional[str]:
    m = (model or "").lower()
    keys = [k.lower() for k in product_keys]
    def find_key(substrings: List[str]) -> Optional[str]:
        for s in substrings:
            for k in keys:
                if s in k:
                    return product_keys[keys.index(k)]
        return None

    if "atem" in m:
        return find_key(["atem"]) or "atem"
    if any(k in m for k in ["ursa", "pyxis", "pocket cinema", "cinema camera", "broadcast"]):
        return find_key(["camera"]) or "camera"
    if "hyperdeck" in m:
        return find_key(["hyperdeck", "disk", "recorder"])
    if "ultrastudio" in m or "recorder" in m:
        hit = find_key(["ultrastudio", "desktop video", "desktopvideo", "capture", "playback", "video"])
        if hit:
            return hit
        for k in product_keys:
            if re.search(r"desktop\\s*video|ultrastudio|capture", k, flags=re.IGNORECASE):
                return k
    if "video assist" in m or "videoassist" in m:
        return find_key(["video", "assist", "monitor"])
    if "audio monitor" in m:
        return find_key(["monitor", "audio"])
    if "converter" in m:
        return find_key(["converter", "broadcast"])
    return None

def blackmagic_support_url(release_id: str, platform: str) -> str:
    plat = parse.quote(platform, safe="")
    return f"https://www.blackmagicdesign.com/support/download/{release_id}/{plat}"

def update_blackmagic_catalog_for_models(models: List[str]) -> None:
    data = fetch_json(BLACKMAGIC_DOWNLOADS_URL)
    if not data or "downloads" not in data:
        log_warn("Blackmagic: failed to fetch downloads.json or missing downloads field.")
        return

    product_latest = {}
    product_keys = set()
    for item in data.get("downloads", []):
        urls = item.get("urls", {})
        for platform, entries in urls.items():
            if not entries:
                continue
            product = entries[0].get("product")
            if not product:
                continue
            product_keys.add(product)
            prev = product_latest.get(product)
            if not prev or item.get("numericDate", 0) > prev.get("numericDate", 0):
                product_latest[product] = item
            break

    if not product_latest:
        return

    if not product_keys:
        log_warn("Blackmagic: no product keys found in downloads data.")

    catalog = load_provider_catalog()
    vendor_block = catalog.get("Blackmagic Design", {})

    for model in models:
        product = blackmagic_product_for_model(model, sorted(product_keys))
        if not product:
            log_warn(f"Blackmagic: no product mapping for model '{model}'.")
            continue
        item = product_latest.get(product)
        if not item:
            log_warn(f"Blackmagic: no latest download found for product '{product}'.")
            continue
        urls = item.get("urls", {})
        platform = "Windows" if "Windows" in urls else (next(iter(urls), None) or "")
        if not platform or not urls.get(platform):
            log_warn(f"Blackmagic: no platform URLs for product '{product}'.")
            continue
        url_entry = urls[platform][0]
        release_id = url_entry.get("releaseId") or item.get("id") or ""
        if not release_id:
            log_warn(f"Blackmagic: missing release id for product '{product}'.")
            continue

        entry = {
            "latest_version": normalize_version(
                url_entry.get("major", 0),
                url_entry.get("minor", 0),
                url_entry.get("releaseNum", 0),
                url_entry.get("buildNum", 0),
            ),
            "url": blackmagic_support_url(release_id, platform) if release_id else "",
            "release_date": item.get("date", ""),
            "notes": item.get("name", ""),
        }

        existing = vendor_block.get(model, {})
        existing.update(entry)
        vendor_block[model] = existing

    catalog["Blackmagic Design"] = vendor_block
    save_provider_catalog(catalog)

def update_roland_catalog_for_models(models: List[str]) -> None:
    pages = load_json_dict(ROLAND_PAGES_PATH, {})
    if not pages:
        return

    pages_norm = {str(k).strip().lower(): v for k, v in pages.items()}
    catalog = load_provider_catalog()
    vendor_block = catalog.get("Roland", {})
    ROLAND_DEBUG_DIR.mkdir(exist_ok=True)
    for model in models:
        model_key = (model or "").strip().lower()
        page_url = pages_norm.get(model_key)
        if not page_url:
            continue
        html = fetch_text(page_url)
        if not html:
            log_warn(f"Roland: failed to fetch page for model '{model}'.")
            existing = vendor_block.get(model, {})
            if "url" not in existing:
                existing["url"] = page_url
            if "notes" not in existing:
                existing["notes"] = "Roland Pro A/V Downloads"
            vendor_block[model] = existing
            continue
        safe_name = re.sub(r"[^a-zA-Z0-9._-]+", "_", model)
        (ROLAND_DEBUG_DIR / f"roland_{safe_name}.html").write_text(html, encoding="utf-8")

        version = None
        release_date = ""
        section_match = re.search(r'<section[^>]*id="dl-drivers"[^>]*>(.*?)</section>', html, flags=re.IGNORECASE | re.DOTALL)
        scope = section_match.group(1) if section_match else html
        scope = html_lib.unescape(scope)
        anchor_re = re.compile(
            r'<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
            flags=re.IGNORECASE | re.DOTALL,
        )
        download_url = ""
        debug_links = []
        link_items = []
        for href, text in anchor_re.findall(scope):
            text_clean = re.sub(r"<[^>]+>", " ", text)
            text_clean = re.sub(r"\\s+", " ", text_clean).strip()
            debug_links.append(text_clean)
            link_items.append((text_clean, href))
            if "system program" not in text_clean.lower():
                continue
            m = re.search(r"ver\\.?\\s*([0-9.]+)", text_clean, flags=re.IGNORECASE)
            if not m:
                continue
            version = m.group(1)
            download_url = parse.urljoin(page_url, href)
            break
        if not version and link_items:
            for text_clean, href in link_items:
                if "system program" not in text_clean.lower():
                    continue
                m = re.search(r"\(\s*ver[^0-9]*([0-9]+(?:\.[0-9]+)+)", text_clean, flags=re.IGNORECASE)
                if not m:
                    m = re.search(r"ver\\.?\\s*([0-9]+(?:\\.[0-9]+)+)", text_clean, flags=re.IGNORECASE)
                if m:
                    version = m.group(1)
                    download_url = parse.urljoin(page_url, href)
                    break
        if not version:
            log_warn(f"Roland: no version found for model '{model}'.")
            matches = re.findall(r"system\\s+program[^\\n\\r]{0,200}?ver\\.?\\s*([0-9.]+)", scope, flags=re.IGNORECASE)
            def ver_key(v: str):
                parts = [int(p) for p in v.split(".") if p.isdigit()]
                return parts + [0] * (4 - len(parts))
            if matches:
                version = sorted({m for m in matches}, key=ver_key)[-1]

        date_match = re.search(r"\[(?:[^\]]*?)\]\s*([A-Za-z]{3,9}\s+\d{4})", scope, flags=re.IGNORECASE)
        if not date_match:
            date_match = re.search(r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\\s+\\d{4}", scope, flags=re.IGNORECASE)
        if date_match:
            release_date = date_match.group(1).strip() if date_match.lastindex else date_match.group(0).strip()

        if not release_date and download_url:
            detail_html = fetch_text(download_url)
            if detail_html:
                detail_match = re.search(r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\s+\d{4}", detail_html, flags=re.IGNORECASE)
                if detail_match:
                    release_date = detail_match.group(0).strip()
            if not release_date:
                log_warn(f"Roland: no release date found on detail page for model '{model}'.")

        existing = vendor_block.get(model, {})
        if version:
            existing["latest_version"] = version
        existing["url"] = download_url or page_url
        existing["release_date"] = release_date
        existing["notes"] = existing.get("notes") or "Roland Pro A/V Downloads"
        vendor_block[model] = existing
        (ROLAND_DEBUG_DIR / f"roland_{safe_name}.txt").write_text(
            f"version={version or ''}\nrelease_date={release_date}\nurl={download_url or page_url}\n",
            encoding="utf-8",
        )

    if vendor_block:
        catalog["Roland"] = vendor_block
        save_provider_catalog(catalog)

def update_panasonic_catalog_for_models(models: List[str]) -> None:
    pages = load_json_dict(PANASONIC_PAGES_PATH, {})
    if not pages:
        return

    pages_norm = {str(k).strip().lower(): v for k, v in pages.items()}
    catalog = load_provider_catalog()
    vendor_block = catalog.get("Panasonic", {})
    PANASONIC_DEBUG_DIR.mkdir(exist_ok=True)

    for model in models:
        page_url = pages_norm.get((model or "").strip().lower())
        if not page_url:
            continue
        html = fetch_text(page_url)
        if not html:
            log_warn(f"Panasonic: failed to fetch page for model '{model}'.")
            continue
        safe_name = re.sub(r"[^a-zA-Z0-9._-]+", "_", model)
        (PANASONIC_DEBUG_DIR / f"panasonic_{safe_name}.html").write_text(html, encoding="utf-8")

        def ver_key(v: str):
            parts = [int(p) for p in v.split(".") if p.isdigit()]
            return parts + [0] * (6 - len(parts))

        version = ""
        release_date = ""
        download_url = page_url

        rows = re.split(r"</tr>", html, flags=re.IGNORECASE)
        candidates = []
        for row in rows:
            if "href" not in row.lower():
                continue
            href_match = re.search(r'href="([^"]+\.htm[^"]*)"', row, flags=re.IGNORECASE)
            if not href_match:
                continue
            text_clean = html_lib.unescape(re.sub(r"<[^>]+>", " ", row))
            text_clean = re.sub(r"\s+", " ", text_clean).strip()

            ver_match = re.search(r"Ver\.?\s*([0-9]+(?:\.[0-9]+)+)", text_clean, flags=re.IGNORECASE)
            if ver_match:
                ver = ver_match.group(1).strip().strip("-")
            else:
                # Handle patterns like "1.84-00-0.00 Download"
                ver_match = re.search(r"\b([0-9]+(?:\.[0-9]+)+(?:-[0-9.]+)?)\b(?=.*Download)", text_clean, flags=re.IGNORECASE)
                if not ver_match:
                    # Derive version from agree/HTML link if present (e.g., hn40_agree_0210e.htm)
                    ver = ""
                    m = re.search(r"_agree_([0-9]{3,4})e\.htm", href_match.group(1), flags=re.IGNORECASE)
                    if not m:
                        m = re.search(r"/([0-9]{3,4})_.*?\.htm", href_match.group(1), flags=re.IGNORECASE)
                    if m:
                        num = m.group(1)
                        ver = f"{int(num[:-2])}.{num[-2:]}"
                        log_warn(f"Panasonic: derived version from href for model '{model}' -> {ver}.")
                    else:
                        continue
                else:
                    ver = ver_match.group(1).strip().strip("-")

            date_match = re.search(r"(Jan\.?|Feb\.?|Mar\.?|Apr\.?|May|Jun\.?|Jul\.?|Aug\.?|Sep\.?|Sept\.?|Oct\.?|Nov\.?|Dec\.?)\s*[^<\n\r]{0,20}\d{1,2}[^<\n\r]{0,6}\d{2,4}", text_clean, flags=re.IGNORECASE)
            date_val = html_lib.unescape(date_match.group(0).strip()) if date_match else ""
            href = parse.urljoin(page_url, href_match.group(1))
            candidates.append((ver, date_val, href))

        if candidates:
            ver, date_val, href = sorted(candidates, key=lambda x: ver_key(x[0]))[-1]
            version = ver
            release_date = date_val
            download_url = page_url
        else:
            log_warn(f"Panasonic: no candidates found in index for model '{model}', falling back to page parse.")
            content_match = re.search(r"Content.*?Ver\.?\s*([0-9]+(?:\.[0-9]+)+)", html, flags=re.IGNORECASE | re.DOTALL)
            if content_match:
                version = content_match.group(1).strip().strip("-")
            else:
                patterns = [
                    r"Firmware\s*Ver\.?\s*([0-9]+(?:\.[0-9]+)+)",
                    r"Software\s*Ver\.?\s*([0-9]+(?:\.[0-9]+)+)",
                    r"System\s*Ver\.?\s*([0-9]+(?:\.[0-9]+)+)",
                    r"\bVer\.?\s*([0-9]+(?:\.[0-9]+)+)",
                    r"Version\s*([0-9]+(?:\.[0-9]+)+)",
                ]
                versions = []
                for pat in patterns:
                    versions.extend(re.findall(pat, html, flags=re.IGNORECASE))
                if versions:
                    version = sorted({v.strip().strip("-") for v in versions}, key=ver_key)[-1]

            date_match = re.search(
                r"Last\s*Update.*?<td[^>]*>\s*([^<]+)\s*</td>",
                html,
                flags=re.IGNORECASE | re.DOTALL,
            )
            if date_match:
                release_date = html_lib.unescape(date_match.group(1).strip())
            else:
                date_match = re.search(r"(Jan\.?|Feb\.?|Mar\.?|Apr\.?|May|Jun\.?|Jul\.?|Aug\.?|Sep\.?|Sept\.?|Oct\.?|Nov\.?|Dec\.?)\\s*[^<\\n\\r]{0,20}\\d{1,2}[^<\\n\\r]{0,6}\\d{2,4}", html, flags=re.IGNORECASE)
                release_date = html_lib.unescape(date_match.group(0).strip()) if date_match else ""
        if not version:
            log_warn(f"Panasonic: no version found for model '{model}'.")
        if not release_date:
            log_warn(f"Panasonic: no release date found for model '{model}'.")

        (PANASONIC_DEBUG_DIR / f"panasonic_{safe_name}.txt").write_text(
            f"version={version}\nrelease_date={release_date}\nurl={download_url}\n",
            encoding="utf-8",
        )

        existing = vendor_block.get(model, {})
        if version:
            existing["latest_version"] = version
        existing["url"] = download_url
        existing["release_date"] = release_date
        existing["notes"] = existing.get("notes") or "Panasonic Pro-AV Downloads"
        vendor_block[model] = existing

    if vendor_block:
        catalog["Panasonic"] = vendor_block
        save_provider_catalog(catalog)

def update_decimator_catalog_for_models(models: List[str]) -> None:
    html = fetch_text(DECIMATOR_DOWNLOADS_URL, verify_ssl=False)
    if not html:
        log_warn("Decimator: failed to fetch downloads page.")
        return
    DECIMATOR_DEBUG_DIR.mkdir(exist_ok=True)
    (DECIMATOR_DEBUG_DIR / "decimator_downloads.html").write_text(html, encoding="utf-8")
    versions = re.findall(r"USB\s+Control\s+Panel\s+Version\s+([0-9.]+)", html, flags=re.IGNORECASE)
    if not versions:
        versions = re.findall(r"USB\s+Control\s+Panel\s*V(?:er)?\.?\s*([0-9.]+)", html, flags=re.IGNORECASE)
    if not versions:
        versions = re.findall(r"USB\s+Control\s+Panel\s*\(.*?\)\s*([0-9.]+)", html, flags=re.IGNORECASE)
    if not versions:
        log_warn("Decimator: no USB Control Panel version found.")
        return
    def ver_key(v: str):
        parts = [int(p) for p in v.split(".") if p.isdigit()]
        return parts + [0] * (6 - len(parts))
    version = sorted({v.strip() for v in versions}, key=ver_key)[-1]

    catalog = load_provider_catalog()
    vendor_block = catalog.get("Decimator", {})
    for model in models:
        existing = vendor_block.get(model, {})
        existing["latest_version"] = version
        existing["url"] = DECIMATOR_DOWNLOADS_URL
        existing["release_date"] = existing.get("release_date", "")
        existing["notes"] = existing.get("notes") or "USB Control Panel"
        vendor_block[model] = existing
    catalog["Decimator"] = vendor_block
    save_provider_catalog(catalog)

def update_provider_for_models(vendor: str, models: List[str]) -> bool:
    if not models:
        return False
    if vendor == "Blackmagic Design":
        update_blackmagic_catalog_for_models(models)
        return True
    if vendor == "Roland":
        update_roland_catalog_for_models(models)
        return True
    if vendor == "Panasonic":
        update_panasonic_catalog_for_models(models)
        return True
    if vendor == "Decimator":
        update_decimator_catalog_for_models(models)
        return True
    log_warn(f"No provider updater for vendor '{vendor}'.")
    return False

def load_json_list(path: Path, fallback: List[str]) -> List[str]:
    if not path.exists():
        log_warn(f"Missing JSON list: {path}")
        return fallback
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            log_warn(f"Invalid JSON list format: {path}")
            return fallback
        return data
    except (OSError, json.JSONDecodeError) as e:
        log_error(f"Failed to load JSON list {path}: {e}")
        return fallback

def load_json_dict(path: Path, fallback: Dict) -> Dict:
    if not path.exists():
        log_warn(f"Missing JSON dict: {path}")
        return fallback
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            log_warn(f"Invalid JSON dict format: {path}")
            return fallback
        return data
    except (OSError, json.JSONDecodeError) as e:
        log_error(f"Failed to load JSON dict {path}: {e}")
        return fallback

def load_fetch_cache() -> Dict[str, str]:
    return load_json_dict(FETCH_CACHE_PATH, {})

def save_fetch_cache(data: Dict[str, str]) -> None:
    try:
        with FETCH_CACHE_PATH.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
    except OSError as e:
        log_error(f"Failed to save fetch cache: {e}")

def is_cache_fresh(iso_ts: Optional[str], ttl_seconds: int) -> bool:
    if not iso_ts:
        return False
    try:
        dt = datetime.datetime.fromisoformat(iso_ts)
    except ValueError:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    age = (datetime.datetime.now(datetime.timezone.utc) - dt).total_seconds()
    return age < ttl_seconds

def format_cache_time(iso_ts: Optional[str]) -> str:
    if not iso_ts:
        return "Never"
    try:
        dt = datetime.datetime.fromisoformat(iso_ts)
    except ValueError:
        return iso_ts
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone().strftime("%m/%d/%Y %I:%M:%S%p")

def next_scrape_time(iso_ts: Optional[str], ttl_seconds: int) -> str:
    if not iso_ts:
        return "Now"
    try:
        dt = datetime.datetime.fromisoformat(iso_ts)
    except ValueError:
        return "Unknown"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    next_dt = dt + datetime.timedelta(seconds=ttl_seconds)
    return next_dt.astimezone().strftime("%m/%d/%Y %I:%M:%S%p")


def fetch_latest_for_device(vendor: str, model: str) -> Optional[dict]:
    vendor_catalog = load_provider_catalog().get(vendor)
    if not vendor_catalog:
        return None
    return vendor_catalog.get(model)


# -------------------------
# UI callbacks
# -------------------------
def build_devices_dataframe():
    devices = list_devices()
    for d in devices:
        d["created_at"] = format_display_datetime(d.get("created_at"))
    return pd.DataFrame(devices)

def devices_table_view(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame(columns=["CATEGORY","VENDOR","MODEL","INSTALLED","NICKNAME","NOTES","CREATED AT"])
    view = df.drop(columns=["id","location","previous_installed_version"], errors="ignore")
    return view.rename(columns={
        "category": "CATEGORY",
        "vendor": "VENDOR",
        "model": "MODEL",
        "installed_version": "INSTALLED",
        "nickname": "NICKNAME",
        "notes": "NOTES",
        "created_at": "CREATED AT",
    })


def refresh_catalog():
    return pd.DataFrame(list_catalog())


def on_add_device(category, vendor, model, installed_version, nickname, notes):
    if not category or not vendor or not model or not installed_version:
        log_warn("Add device: missing required fields.")
    add_device(category, vendor, model, installed_version, nickname, notes)
    df = build_devices_dataframe()
    return df, devices_table_view(df)


def on_delete_device(device_id):
    delete_device(device_id)
    df = build_devices_dataframe()
    return df, devices_table_view(df)

def on_delete_selected(device_id, confirm_delete):
    if not device_id or not confirm_delete:
        df = build_devices_dataframe()
        return df, devices_table_view(df), gr.update(value=False)
    delete_device(device_id)
    df = build_devices_dataframe()
    return df, devices_table_view(df), gr.update(value=False)

def on_update_device(device_id, category, vendor, model, installed_version, nickname, notes):
    if not device_id:
        df = build_devices_dataframe()
        return df, devices_table_view(df)
    if not category or not vendor or not model or not installed_version:
        log_warn(f"Update device {device_id}: missing required fields.")
    update_device(device_id, category, vendor, model, installed_version, nickname, notes)
    df = build_devices_dataframe()
    return df, devices_table_view(df)

def get_device_by_id(device_id: int) -> Optional[dict]:
    try:
        conn = db()
        row = conn.execute("SELECT * FROM devices WHERE id = ?", (int(device_id),)).fetchone()
        conn.close()
        return dict(row) if row else None
    except sqlite3.Error as e:
        log_error(f"Get device failed: {e}")
        return None

def mark_device_updated(device_id: int) -> None:
    device = get_device_by_id(device_id)
    if not device:
        return
    entry = fetch_latest_for_device(device["vendor"], device["model"])
    latest = entry.get("latest_version") if entry else None
    if not latest:
        return
    update_device(
        device_id,
        device["category"],
        device["vendor"],
        device["model"],
        latest,
        device.get("nickname") or "",
        device.get("notes") or "",
    )

def on_device_select(full_df, evt: gr.SelectData):
    if full_df is None or len(full_df) == 0:
        return (
            gr.update(value=0),
            gr.update(value="Camera"),
            gr.update(value="Blackmagic Design"),
            gr.update(choices=model_choices_for_vendor("Blackmagic Design"), value=""),
            gr.update(value=""),
            gr.update(value=""),
            gr.update(value=""),
            gr.update(value=""),
            gr.update(value=""),
        )
    row_index = evt.index[0] if isinstance(evt.index, (list, tuple)) else evt.index
    row = full_df.iloc[row_index] if hasattr(full_df, "iloc") else full_df[row_index]
    display_name = row.get("nickname") or f'{row["vendor"]} {row["model"]}'
    return (
        gr.update(value=int(row["id"])),
        gr.update(value=row["category"]),
        gr.update(value=row["vendor"]),
        gr.update(choices=model_choices_for_vendor(row["vendor"]), value=row["model"]),
        gr.update(value=row["installed_version"]),
        gr.update(value=row.get("nickname") or ""),
        gr.update(value=row.get("notes") or ""),
        gr.update(value=display_name),
        gr.update(value=row.get("created_at") or ""),
    )

def on_upsert_catalog(vendor, model, latest_version, url, release_date, notes):
    upsert_catalog(vendor, model, latest_version, url, release_date, notes)
    return refresh_catalog()


def on_delete_catalog(row_id):
    delete_catalog_row(row_id)
    return refresh_catalog()


def build_update_choices(full_df: pd.DataFrame):
    if full_df is None or full_df.empty:
        return gr.update(choices=[], value=[])
    choices = []
    for _, row in full_df.iterrows():
        if row.get("status_code") != "update_available":
            continue
        label = f'{row["device"]} ({row["vendor"]} {row["model"]}) → {row["latest"]}'
        choices.append((label, int(row["device_id"])))
    return gr.update(choices=choices, value=[])

def build_updates(scrape: bool, force: bool = False):
    devices = list_devices()
    cache = load_fetch_cache()
    cache_updated = False
    if scrape:
        blackmagic_models = sorted({d["model"] for d in devices if d["vendor"] == "Blackmagic Design"})
        if blackmagic_models and (force or not is_cache_fresh(cache.get("Blackmagic Design"), CACHE_TTL_SECONDS)):
            try:
                if update_provider_for_models("Blackmagic Design", blackmagic_models):
                    cache["Blackmagic Design"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    cache_updated = True
            except Exception as e:
                log_error(f"Blackmagic update failed: {e}")
        roland_models = sorted({d["model"] for d in devices if d["vendor"] == "Roland"})
        if roland_models and (force or not is_cache_fresh(cache.get("Roland"), CACHE_TTL_SECONDS)):
            try:
                if update_provider_for_models("Roland", roland_models):
                    cache["Roland"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    cache_updated = True
            except Exception as e:
                log_error(f"Roland update failed: {e}")
        decimator_models = sorted({d["model"] for d in devices if d["vendor"] == "Decimator"})
        if decimator_models and (force or not is_cache_fresh(cache.get("Decimator"), CACHE_TTL_SECONDS)):
            try:
                if update_provider_for_models("Decimator", decimator_models):
                    cache["Decimator"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    cache_updated = True
            except Exception as e:
                log_error(f"Decimator update failed: {e}")
        panasonic_models = sorted({d["model"] for d in devices if d["vendor"] == "Panasonic"})
        if panasonic_models and (force or not is_cache_fresh(cache.get("Panasonic"), CACHE_TTL_SECONDS)):
            try:
                if update_provider_for_models("Panasonic", panasonic_models):
                    cache["Panasonic"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    cache_updated = True
            except Exception as e:
                log_error(f"Panasonic update failed: {e}")
    if cache_updated:
        save_fetch_cache(cache)
    results = []
    any_metadata = False
    decimator_link_added = False
    for d in devices:
        if not d.get("vendor") or not d.get("model"):
            log_warn(f"Device missing vendor/model: id={d.get('id')}")
        entry = fetch_latest_for_device(d["vendor"], d["model"])
        latest = entry.get("latest_version") if entry else None
        status = compare_versions(d["installed_version"], latest)
        last_checked = format_cache_time(cache.get(d["vendor"]))
        if not latest and last_checked != "Never":
            log_warn(f"No latest version for {d['vendor']} {d['model']} despite recent check.")
        code = status_code(status, last_checked, bool(latest))
        show_url = code == "update_available"
        has_metadata = bool(entry and entry.get("release_date"))
        any_metadata = any_metadata or has_metadata
        status_display = format_status(code, last_checked)

        results.append({
            "device_id": d["id"],
            "device": d.get("nickname") or f'{d["vendor"]} {d["model"]}',
            "vendor": d["vendor"],
            "model": d["model"],
            "installed": d["installed_version"],
            "latest": latest or "",
            "previous_installed": d.get("previous_installed_version") or "",
            "status": status_display,
            "status_code": code,
            "url": (entry["url"] if entry else "") if show_url else "",
            "last_checked": last_checked,
            "release_date": (entry["release_date"] if entry else "") or "",
        })
    full_df = pd.DataFrame(results)
    links = []
    for r in results:
        if r.get("status_code") == "update_available":
            if r.get("vendor") == "Decimator":
                if not decimator_link_added and r.get("url"):
                    links.append(f'<li><a href="{r["url"]}" target="_blank" rel="noopener noreferrer">Decimator USB Control Panel</a></li>')
                    decimator_link_added = True
            elif r.get("url"):
                label = f'{r["device"]} ({r["vendor"]} {r["model"]})'
                links.append(f'<li><a href="{r["url"]}" target="_blank" rel="noopener noreferrer">{label}</a></li>')
    links_html = "<ul>" + "".join(links) + "</ul>" if links else "<em>No download links available.</em>"
    header_labels = {
        "device": "DEVICE",
        "vendor": "VENDOR",
        "model": "MODEL",
        "installed": "INSTALLED",
        "latest": "LATEST",
        "previous_installed": "PREVIOUS",
        "status": "STATUS",
        "last_checked": "LAST CHECKED",
        "release_date": "RELEASE DATE",
    }
    if any_metadata:
        headers = ["device","vendor","model","installed","latest","previous_installed","status","last_checked","release_date"]
    else:
        headers = ["device","vendor","model","installed","latest","previous_installed","status","last_checked"]
    display_headers = [header_labels[h] for h in headers]
    view_df = full_df.drop(columns=["device_id","url","status_code"], errors="ignore")
    if not view_df.empty:
        view_df = view_df.reindex(columns=headers)
        view_df = view_df.rename(columns=header_labels)
    bulk_choices = build_update_choices(full_df)
    vendor_times = []
    for v in {d["vendor"] for d in devices}:
        ts = cache.get(v)
        if ts:
            vendor_times.append(ts)
    if vendor_times:
        latest_ts = max(vendor_times)
        next_allowed = next_scrape_time(latest_ts, CACHE_TTL_SECONDS)
    else:
        next_allowed = "Now"
    status_md = f"Next full scrape available at: {next_allowed}"
    return full_df, gr.update(value=view_df, headers=display_headers), gr.update(value=links_html), bulk_choices, gr.update(value=status_md)

def on_check_updates():
    return build_updates(scrape=True)

def on_force_full_scrape():
    return build_updates(scrape=True, force=True)

def on_check_updates_no_scrape():
    return build_updates(scrape=False)

def on_updates_select(full_df, evt: gr.SelectData):
    if full_df is None or len(full_df) == 0:
        return gr.update(value=0), gr.update(value="")
    row_index = evt.index[0] if isinstance(evt.index, (list, tuple)) else evt.index
    row = full_df.iloc[row_index] if hasattr(full_df, "iloc") else full_df[row_index]
    label = f'{row["device"]} ({row["vendor"]} {row["model"]})'
    return gr.update(value=int(row["device_id"])), gr.update(value=label)

def on_check_selected_updates(device_id):
    if not device_id:
        full_df, updates_table, links_html, bulk_choices, status_md = build_updates(scrape=False)
        devices_df = build_devices_dataframe()
        return full_df, updates_table, links_html, bulk_choices, status_md, devices_df, devices_table_view(devices_df)
    device = get_device_by_id(device_id)
    if not device:
        full_df, updates_table, links_html, bulk_choices, status_md = build_updates(scrape=False)
        devices_df = build_devices_dataframe()
        return full_df, updates_table, links_html, bulk_choices, status_md, devices_df, devices_table_view(devices_df)
    cache = load_fetch_cache()
    vendor = device["vendor"]
    model = device["model"]
    try:
        if update_provider_for_models(vendor, [model]):
            cache[vendor] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            save_fetch_cache(cache)
    except Exception as e:
        log_error(f"Update check failed for {vendor} {model}: {e}")
    full_df, updates_table, links_html, bulk_choices, status_md = build_updates(scrape=False)
    devices_df = build_devices_dataframe()
    return full_df, updates_table, links_html, bulk_choices, status_md, devices_df, devices_table_view(devices_df)

def on_bulk_mark_updated(device_ids: List[int]):
    if not device_ids:
        full_df, updates_table, links_html, bulk_choices, status_md = build_updates(scrape=False)
        devices_df = build_devices_dataframe()
        return full_df, updates_table, links_html, bulk_choices, status_md, devices_df, devices_table_view(devices_df)
    for device_id in device_ids:
        mark_device_updated(device_id)
    full_df, updates_table, links_html, bulk_choices, status_md = build_updates(scrape=False)
    devices_df = build_devices_dataframe()
    return full_df, updates_table, links_html, bulk_choices, status_md, devices_df, devices_table_view(devices_df)

def get_logs_df() -> pd.DataFrame:
    if not LOG_BUFFER:
        return pd.DataFrame(columns=["TIME","LEVEL","MESSAGE"])
    df = pd.DataFrame(LOG_BUFFER)
    return df.rename(columns={"time": "TIME", "level": "LEVEL", "message": "MESSAGE"})

def on_refresh_logs():
    return get_logs_df()

def on_clear_logs():
    LOG_BUFFER.clear()
    return get_logs_df()

def on_use_db(path: str):
    set_db_path(path)
    init_db()
    return CURRENT_DB_PATH


# -------------------------
# Build app
# -------------------------
init_db()

CATEGORIES = ["Switcher", "Camera", "PTZ", "Controller", "Encoder", "Other"]
VENDORS = ["Blackmagic Design", "Roland", "Panasonic", "Sony", "Canon", "Other"]
CATEGORIES = load_json_list(CATEGORIES_PATH, CATEGORIES)
VENDORS = load_json_list(VENDORS_PATH, VENDORS)
MODEL_OPTIONS = load_json_dict(MODEL_OPTIONS_PATH, {
    "Blackmagic Design": [],
    "Roland": [],
    "Panasonic": [],
    "Sony": [],
    "Canon": [],
    "Other": [],
})

def model_choices_for_vendor(vendor: str) -> List[str]:
    return MODEL_OPTIONS.get(vendor, [])

def on_vendor_change(vendor: str):
    choices = model_choices_for_vendor(vendor)
    return gr.update(choices=choices, value="")

TABLE_CSS = """
#devices_table .gr-dataframe {
    overflow-x: auto;
}
#devices_table table {
    width: 100%;
    table-layout: auto;
}
#devices_table th,
#devices_table td {
    padding-right: 12px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 220px;
}
#devices_table th:nth-child(6),
#devices_table td:nth-child(6) {
    max-width: 360px;
}
#devices_table th:nth-child(7),
#devices_table td:nth-child(7) {
    max-width: 180px;
}
"""

with gr.Blocks(title="Firmware Tracker") as demo:
    gr.Markdown("# Firmware Tracker\nSingle-inventory tracker with manual firmware catalog + update check.")

    with gr.Tab("Devices (Installed)"):
        with gr.Row():
            category = gr.Dropdown(CATEGORIES, value="Camera", label="Category")
            vendor = gr.Dropdown(VENDORS, value="Blackmagic Design", label="Vendor")
            model = gr.Dropdown(
                choices=model_choices_for_vendor("Blackmagic Design"),
                value="",
                allow_custom_value=True,
                label="Model",
            )
        with gr.Row():
            installed_version = gr.Textbox(label="Installed firmware", placeholder="e.g. 9.1.2")
            nickname = gr.Textbox(label="Nickname (optional)", placeholder="FOH Cam 1")
        notes = gr.Textbox(label="Notes (optional)", lines=2)

        add_device_btn = gr.Button("Add device")
        devices_state = gr.State(build_devices_dataframe())
        devices_table = gr.Dataframe(
            headers=["CATEGORY","VENDOR","MODEL","INSTALLED","NICKNAME","NOTES","CREATED AT"],
            interactive=False,
            elem_id="devices_table",
            label="Saved devices"
        )

        add_device_btn.click(
            on_add_device,
            inputs=[category, vendor, model, installed_version, nickname, notes],
            outputs=[devices_state, devices_table]
        )
        vendor.change(on_vendor_change, inputs=[vendor], outputs=[model])

        with gr.Row():
            gr.Markdown("### Selected device")
        with gr.Row():
            detail_name = gr.Textbox(label="Device", interactive=False)
            detail_category = gr.Dropdown(CATEGORIES, value="Camera", label="Category")
            detail_vendor = gr.Dropdown(VENDORS, value="Blackmagic Design", label="Vendor")
        with gr.Row():
            detail_model = gr.Dropdown(
                choices=model_choices_for_vendor("Blackmagic Design"),
                value="",
                allow_custom_value=True,
                label="Model",
            )
            detail_installed = gr.Textbox(label="Installed firmware")
            detail_nickname = gr.Textbox(label="Nickname")
        with gr.Row():
            detail_created_at = gr.Textbox(label="Created at", interactive=False)
        detail_notes = gr.Textbox(label="Notes", lines=4)
        edit_device_id = gr.State(0)
        edit_save_btn = gr.Button("Update device")
        edit_confirm_delete = gr.Checkbox(label="Confirm delete", value=False)
        edit_delete_btn = gr.Button("Delete selected device")

        devices_table.select(
            on_device_select,
            inputs=[devices_state],
            outputs=[
                edit_device_id, detail_category, detail_vendor, detail_model, detail_installed, detail_nickname, detail_notes,
                detail_name, detail_created_at,
            ],
        )
        edit_save_btn.click(
            on_update_device,
            inputs=[edit_device_id, detail_category, detail_vendor, detail_model, detail_installed, detail_nickname, detail_notes],
            outputs=[devices_state, devices_table],
        )
        detail_vendor.change(on_vendor_change, inputs=[detail_vendor], outputs=[detail_model])
        edit_delete_btn.click(
            on_delete_selected,
            inputs=[edit_device_id, edit_confirm_delete],
            outputs=[devices_state, devices_table, edit_confirm_delete],
        )
        demo.load(lambda: (build_devices_dataframe(), devices_table_view(build_devices_dataframe())), outputs=[devices_state, devices_table])

    with gr.Tab("Updates"):
        gr.Markdown("Shows update status for devices in your inventory.")
        check_btn = gr.Button("Refresh updates")
        force_scrape_btn = gr.Button("Force full scrape (debug)")
        updates_state = gr.State(pd.DataFrame())
        cache_status = gr.Markdown("")
        results_table = gr.Dataframe(
            headers=["DEVICE","VENDOR","MODEL","INSTALLED","LATEST","PREVIOUS","STATUS","LAST CHECKED","RELEASE DATE"],
            interactive=False,
            label="Results"
        )
        selected_update_id = gr.State(0)
        selected_update_label = gr.Textbox(label="Selected device", interactive=False)
        check_selected_btn = gr.Button("Check selected for updates")
        bulk_update_ids = gr.CheckboxGroup(label="Bulk mark updated", choices=[])
        bulk_mark_btn = gr.Button("Mark checked as updated")
        links_html = gr.HTML(label="Download links")
        check_btn.click(on_check_updates, outputs=[updates_state, results_table, links_html, bulk_update_ids, cache_status])
        force_scrape_btn.click(on_force_full_scrape, outputs=[updates_state, results_table, links_html, bulk_update_ids, cache_status])
        results_table.select(on_updates_select, inputs=[updates_state], outputs=[selected_update_id, selected_update_label])
        check_selected_btn.click(
            on_check_selected_updates,
            inputs=[selected_update_id],
            outputs=[updates_state, results_table, links_html, bulk_update_ids, cache_status, devices_state, devices_table],
        )
        bulk_mark_btn.click(
            on_bulk_mark_updated,
            inputs=[bulk_update_ids],
            outputs=[updates_state, results_table, links_html, bulk_update_ids, cache_status, devices_state, devices_table],
        )
        demo.load(on_check_updates, outputs=[updates_state, results_table, links_html, bulk_update_ids, cache_status])

    with gr.Tab("Diagnostics"):
        gr.Markdown("Warnings and errors logged by the app (most recent first).")
        with gr.Row():
            refresh_logs_btn = gr.Button("Refresh logs")
            clear_logs_btn = gr.Button("Clear logs")
        current_db = gr.Textbox(label="Current DB", interactive=False)
        with gr.Row():
            use_main_db_btn = gr.Button("Use main DB")
            use_test_db_btn = gr.Button("Use test DB")
        logs_table = gr.Dataframe(
            headers=["TIME","LEVEL","MESSAGE"],
            interactive=False,
            label="Log entries"
        )
        refresh_logs_btn.click(on_refresh_logs, outputs=[logs_table])
        clear_logs_btn.click(on_clear_logs, outputs=[logs_table])
        use_main_db_btn.click(lambda: on_use_db(DEFAULT_DB_PATH), outputs=[current_db])
        use_test_db_btn.click(lambda: on_use_db(TEST_DB_PATH), outputs=[current_db])
        demo.load(on_refresh_logs, outputs=[logs_table])
        demo.load(lambda: CURRENT_DB_PATH, outputs=[current_db])

demo.launch(server_name="0.0.0.0", server_port=7860, css=TABLE_CSS)
