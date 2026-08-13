@echo off
REM =====================================================================
REM  websec-auditor launcher  (double-click to run)
REM  Starts the bundled flawed demo target (:8099) and the web UI (:8000),
REM  then opens the UI in your default browser. Standard library only.
REM =====================================================================
SETLOCAL ENABLEEXTENSIONS

REM --- locate a real Windows Python 3.10+ (pin 3.12 first, then fall back) ---
SET "PYTHON="
IF EXIST "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    SET "PYTHON=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
) ELSE IF EXIST "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    SET "PYTHON=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
) ELSE IF EXIST "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" (
    SET "PYTHON=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
) ELSE (
    SET "PYTHON=python"
)

REM Project folder = where this .bat lives (D:\websec-auditor)
SET "PROJ=%~dp0"
REM normalise trailing backslash for py path insert
SET "PROJPY=%PROJ:\=/%"

CD /D "%PROJ%"

REM sanity: python must exist and import the package
"%PYTHON%" --version >NUL 2>&1
IF ERRORLEVEL 1 (
    echo [X] Python not found. Install Python 3.10+ from python.org and re-run.
    pause
    EXIT /B 1
)

echo [websec-auditor] using python:
"%PYTHON%" --version

REM verify the package + stdlib imports actually resolve (no silent failure)
"%PYTHON%" -c "import sys; sys.path.insert(0,r'%PROJPY%'); import websec_auditor.webui, websec_auditor.demo.flawed_server, websec_auditor.fixgen; print('imports OK')" 2>&1
IF ERRORLEVEL 1 (
    echo [X] Failed to import websec_auditor. See errors above.
    pause
    EXIT /B 1
)

echo [websec-auditor] building knowledge base (one-time)...
"%PYTHON%" -c "import sys; sys.path.insert(0,r'%PROJPY%'); from websec_auditor.knowledge import build_kb; build_kb.write_kb()" 2>&1

REM Reset the demo target to FLAWED state so the scan/fix proof loop is reproducible.
"%PYTHON%" -c "import sys; sys.path.insert(0,r'%PROJPY%'); from websec_auditor import fixgen; fixgen.reset_demo_fix()" 2>&1

echo [websec-auditor] starting backend servers...
start "websec-demo" /MIN "%PYTHON%" -m websec_auditor.demo.flawed_server
start "websec-ui"   /MIN "%PYTHON%" -m websec_auditor.webui 8000

REM Wait until both ports are actually listening (real check, not a fixed sleep)
echo [websec-auditor] waiting for servers to bind...
SET /A "TRIES=0"
:waitloop
IF %TRIES% GEQ 30 GOTO waitexit
"%PYTHON%" -c "import socket,sys; s=socket.socket(); s.settimeout(1);
ok=all(0==s.connect_ex(('127.0.0.1',p)) for p in (8000,8099)); sys.exit(0 if ok else 1)" >NUL 2>&1
IF NOT ERRORLEVEL 1 GOTO serversup
SET /A "TRIES+=1"
timeout /t 1 >NUL 2>&1
GOTO waitloop
:waitexit
echo [!] servers did not bind within 30s -- check the minimized windows for errors.
GOTO openbrowser
:serversup
echo [websec-auditor] servers are up.

:openbrowser
echo [websec-auditor] opening frontend in your browser...
start "" "http://127.0.0.1:8000/"

echo.
echo  Backend running:
echo    Frontend (UI) : http://127.0.0.1:8000/
echo    Demo target   : http://127.0.0.1:8099/   (paste this into the UI)
echo.
echo  Close the two minimized python windows to stop the servers.
echo  (This window can be closed; backend keeps running in background.)
ENDLOCAL
