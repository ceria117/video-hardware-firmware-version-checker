# Firmware Tracker

## Install / update (auto-updating)
Run this first (and any time you want to update):
- Windows: `install_update.bat`
- macOS/Linux: `bash install_update.sh`

## Run
- Windows: `run.bat`
- macOS/Linux: `bash run.sh`

## Config (optional)
Create `config.json` (copy from `config.json.example`) to override defaults:
- `server_name` (default `0.0.0.0`)
- `server_port` (default `7860`)
- `db_path` (default `firmware_tracker.sqlite3`)
- `scrape_ttl_minutes` (default `60`)

## Friendly URL over Tailscale (optional)
Use MagicDNS to get a stable hostname like `raspi3.tailnet-xxxx.ts.net`.
If you want no port in the URL, use Caddy:
1) Install Caddy on your machine.
2) Copy `Caddyfile.example` to `Caddyfile` and replace the hostname.
3) Run `caddy run` (or set it up as a service).

## Notes
- Auto-update runs `git pull` if a `.git` folder exists and Git is installed.
- Requires Python 3.10+.
