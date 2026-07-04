@echo off
REM ============================================================
REM   MONITOR DE RED - Lanzador (doble clic para iniciar)
REM ============================================================
REM  - Se auto-eleva a Administrador (para ver todas las
REM    conexiones del sistema, no solo las tuyas).
REM  - Instala las dependencias solo la primera vez.
REM  - Arranca la app y abre el dashboard en el navegador.
REM ============================================================

REM --- Comprobar si ya somos Administrador ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Solicitando permisos de Administrador...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

REM --- Situarse en la carpeta de la app ---
cd /d "%~dp0"

echo ============================================================
echo    MONITOR DE RED PERSONAL
echo ============================================================
echo.

REM --- Verificar que Python esta instalado ---
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] No se encuentra Python.
    echo Instalalo desde https://www.python.org/downloads/
    echo y marca la casilla "Add Python to PATH".
    echo.
    pause
    exit /b
)

REM --- Instalar dependencias solo si faltan ---
python -c "import flask, psutil, requests" >nul 2>&1
if %errorlevel% neq 0 (
    echo Instalando dependencias por primera vez, espera un momento...
    python -m pip install -r requirements.txt
    echo.
)

echo Iniciando el monitor... el dashboard se abrira solo en el navegador.
echo Para DETENER la app: cierra esta ventana o pulsa Ctrl+C.
echo ============================================================
echo.

python -m app.main

REM Si la app termina o falla, mantener la ventana abierta para ver el motivo
echo.
echo La aplicacion se ha detenido.
pause
