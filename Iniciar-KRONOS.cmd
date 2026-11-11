@echo off
setlocal
set "AVALONIA_TELEMETRY_OPTOUT=1"
set "DOTNET_CLI_TELEMETRY_OPTOUT=1"
cd /d "%~dp0"
if exist "artifacts\win-x64\Kronos.Desktop.exe" (
  start "" "artifacts\win-x64\Kronos.Desktop.exe"
  exit /b 0
)
if exist ".tools\dotnet\dotnet.exe" (
  set "DOTNET_CLI_HOME=%CD%\.tools\cli"
  set "NUGET_PACKAGES=%CD%\.tools\packages"
  ".tools\dotnet\dotnet.exe" run --project src\Kronos.Desktop -c Release
  exit /b %errorlevel%
)
echo No hay publicacion preparada. Consulta README.md para compilar con .NET 10.
pause
exit /b 1
