@echo off
setlocal

if not exist ".venv\Scripts\activate" (
  echo Virtual environment not found. Run install_update.bat first.
  pause
  exit /b 1
)

call .venv\Scripts\activate
python app.py
pause
