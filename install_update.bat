@echo off
setlocal

if exist ".git" (
  where git >nul 2>nul
  if %errorlevel%==0 (
    git pull
  ) else (
    echo Git not found; skipping auto-update.
  )
) else (
  echo No .git folder; skipping auto-update.
)

python -m venv .venv
call .venv\Scripts\activate
pip install -r requirements.txt

echo Install/update complete. Run run.bat to start.
pause
