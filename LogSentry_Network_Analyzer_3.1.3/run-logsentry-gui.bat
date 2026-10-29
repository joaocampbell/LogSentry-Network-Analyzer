@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo ERRO: O ambiente virtual .venv nao existe.
    echo Executa primeiro: python -m venv .venv
    pause
    exit /b 1
)

".venv\Scripts\python.exe" -m netanalyzer.gui

if errorlevel 1 (
    echo.
    echo LogSentry nao iniciou. Verifica as dependencias e o erro acima.
    pause
)
endlocal
