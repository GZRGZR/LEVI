@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if errorlevel 1 (
  echo Python Launcher was not found.
  echo Install Python 3 from python.org and include Tcl/Tk.
  pause
  exit /b 1
)
py -3 -c "import tkinter" >nul 2>&1
if errorlevel 1 (
  echo Tkinter is unavailable. Re-run the Python installer and include Tcl/Tk.
  pause
  exit /b 1
)
py -3 -c "import psutil" >nul 2>&1
if errorlevel 1 (
  echo Installing the single required package psutil from PyPI...
  echo Internet is needed only for this installation; the app itself does not use the network.
  py -3 -m pip install --user -r requirements.txt
  if errorlevel 1 (
    echo Install failed. Try: py -3 -m pip install --user -r requirements.txt
    pause
    exit /b 1
  )
)
py -3 app.py
if errorlevel 1 pause
endlocal
