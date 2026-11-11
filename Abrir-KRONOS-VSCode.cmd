@echo off
setlocal
cd /d "%~dp0"
if not exist ".tools\dotnet\dotnet.exe" (
  echo No existe el SDK local. Abre esta carpeta en un Dev Container para usar .NET 10.
  pause
  exit /b 1
)
set "DOTNET_ROOT=%CD%\.tools\dotnet"
set "PATH=%DOTNET_ROOT%;%PATH%"
set "DOTNET_CLI_HOME=%CD%\.tools\cli"
set "NUGET_PACKAGES=%CD%\.tools\packages"
set "DOTNET_CLI_TELEMETRY_OPTOUT=1"
set "AVALONIA_TELEMETRY_OPTOUT=1"
call code --new-window --user-data-dir "%CD%\.tools\vscode-local" "%CD%"
exit /b %errorlevel%
