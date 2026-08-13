@echo off
REM =====================================================================
REM  websec-auditor launcher  (double-click to run)
REM  Starts the backend (web UI + bundled demo target) and opens the
REM  frontend (browser) automatically. No pip install needed (stdlib).
REM
REM  FIX (2026-08-12): the launcher no longer trusts `python` on PATH
REM  because on this machine `python` resolves to the Windows Store
REM  redirector (AppInstallerPythonRedirector.exe), which silently
REM  fails / opens the Store instead of running the app. We now locate
REM  a REAL python.exe explicitly and log all output so failures are
REM  visible instead of dying silently.
REM =====================================================================

SETLOCAL ENABLEEXTENSIONS
REM Project folder = where this .bat lives (D:\websec-auditor)
SET "PROJ=%~dp0"
REM Normalise trailing backslash for path joins below.
IF "%PROJ:~-1%"=="\" SET "PROJ=%PROJ:~0,-1%"

REM ---- Locate a real python.exe (explicit, not the Store redirector) ----
SET "PYTHON="
REM 1) py launcher (best)
WHERE py >NUL 2>&1 && FOR /F "tokens=*" %%P IN ('py -3.12 -c "import sys;print(sys.executable)" 2^>NUL') DO SET "PYTHON=%%P"
REM 2) common install locations
IF NOT DEFINED PYTHON (
  FOR %%D IN (
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python39\python.exe"
    "C:\Python312\python.exe"
    "C:\Python311\python.exe"
    "C:\Python310\python.exe"
  ) DO (
    IF NOT DEFINED PYTHON IF EXIST "%%D" SET "PYTHON=%%D"
  )
)
REM 3) last resort: whatever `python` resolves to (may be Store redirector)
IF NOT DEFINED PYTHON (
  WHERE python >NUL 2>&1 && FOR /F "tokens=*" %%P IN ('python -c "import sys;print(sys.executable)" 2^>NUL') DO SET "PYTHON=%%P"
)

IF NOT DEFINED PYTHON (
  echo [X] No real Python found. Install Python 3.10+ from python.org and re-run.
  pause
  EXIT /B 1
)
echo [websec-auditor] using python: %PYTHON%

REM Always run from the project folder so the package imports resolve.
CD /D "%PROJ%"

REM sanity: python must import our package
"%PYTHON%" -c "import sys; sys.path.insert(0,r'%PROJ%'); import websec_auditor" 2>&1
IF ERRORLEVEL 1 (
  echo [X] Python found but cannot import websec_auditor. See error above.
  pause
  EXIT /B 1
)

REM ---- log dir for server output (so failures are visible) ----
SET "LOGDIR=%PROJ%\logs"
IF NOT EXIST "%LOGDIR%" MKDIR "%LOGDIR%"

echo [websec-auditor] building knowledge base (one-time)...
"%PYTHON%" -c "import sys; sys.path.insert(0,r'%PROJ%'); from websec_auditor.knowledge import build_kb; build_kb.write_kb()"

REM Reset the demo target to FLAWED state so the scan/fix proof loop is
REM reproducible on every launch (clears any prior "fixed" state).
"%PYTHON%" -c "import sys; sys.path.insert(0,r'%PROJ%'); from websec_auditor import fixgen; fixgen.reset_demo_fix()"

REM ---- avoid double-launch: skip if ports already in use ----
SET "DEMO_UP=0"
SET "UI_UP=0"
("%PYTHON%" -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1',8099)); s.close()" >NUL 2>&1) && SET "DEMO_UP=1"
("%PYTHON%" -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1',8000)); s.close()" >NUL 2>&1) && SET "UI_UP=1"

IF "%DEMO_UP%"=="1" (echo [!] demo target :8099 already running) ELSE (
  echo [websec-auditor] starting demo target on :8099 ...
  start "websec-demo" /MIN "%PYTHON%" -m websec_auditor.demo.flawed_server >"%LOGDIR%\demo.log" 2>&1
)
IF "%UI_UP%"=="1" (echo [!] web UI :8000 already running) ELSE (
  echo [websec-auditor] starting web UI on :8000 ...
  start "websec-ui" /MIN "%PYTHON%" -m websec_auditor.webui 8000 >"%LOGDIR%\ui.log" 2>&1
)

REM give the servers a moment to bind
ping -n 3 127.0.0.1 >NUL 2>&1

echo [websec-auditor] opening frontend in your browser...
start "" "http://127.0.0.1:8000/"

echo.
echo  Backend running:
echo    Frontend (UI) : http://127.0.0.1:8000/
echo    Demo target   : http://127.0.0.1:8099/   (paste this into the UI)
echo.
echo  Close the two minimized python windows (or logs\demo.log / ui.log)
echo  to stop the servers. This window can be closed.
echo.
echo  If the browser does not open or the scan fails, check:
echo    %LOGDIR%\demo.log
echo    %LOGDIR%\ui.log
echo.

ENDLOCAL
