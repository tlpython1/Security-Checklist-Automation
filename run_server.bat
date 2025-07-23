@echo off
REM Security Checklist Automation - Server Startup Script (Windows)
REM This script activates the virtual environment and starts the FastAPI server

title Security Checklist Automation Server

echo.
echo ===============================================
echo   Security Checklist Automation Server
echo ===============================================
echo.

REM Get the directory where the script is located
cd /d "%~dp0"

REM Check if virtual environment exists
if not exist "venv" (
    echo [WARNING] Virtual environment not found. Creating one...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
    echo [SUCCESS] Virtual environment created successfully
)

REM Activate virtual environment
echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat

if errorlevel 1 (
    echo [ERROR] Failed to activate virtual environment
    pause
    exit /b 1
)

echo [SUCCESS] Virtual environment activated

REM Check if requirements are installed
echo [INFO] Checking dependencies...
python -c "import fastapi, uvicorn" >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Dependencies not found. Installing from requirements.txt...
    
    if not exist "requirements.txt" (
        echo [ERROR] requirements.txt not found
        pause
        exit /b 1
    )
    
    python -m pip install --upgrade pip
    pip install -r requirements.txt
    
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
    
    echo [SUCCESS] Dependencies installed successfully
) else (
    echo [SUCCESS] Dependencies are already installed
)

REM Change to app directory
cd app

REM Check if main.py exists
if not exist "main.py" (
    echo [ERROR] main.py not found in app directory
    pause
    exit /b 1
)

REM Display server information
echo.
echo Server Configuration:
echo   Host: 0.0.0.0
echo   Port: 8081
echo   URL:  http://localhost:8081
echo   Docs: http://localhost:8081/docs
echo.

REM Start the FastAPI server
echo [INFO] Starting FastAPI server...
echo Press Ctrl+C to stop the server
echo.

uvicorn main:app --reload --host 0.0.0.0 --port 8081

REM Deactivate virtual environment when server stops
echo.
echo [INFO] Server stopped. Deactivating virtual environment...
call deactivate
echo [SUCCESS] Cleanup completed
pause
