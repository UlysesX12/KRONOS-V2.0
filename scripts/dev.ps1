# Copyright (c) 2026 Jose Luis Cabanas (JLC / UlysesX12). See LICENSE.md.
param([ValidateSet('Restore','Build','Test','Run')][string]$Action = 'Test')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $projectRoot
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:AVALONIA_TELEMETRY_OPTOUT = '1'
$env:DOTNET_CLI_HOME = Join-Path $projectRoot '.tools\cli'
$env:NUGET_PACKAGES = Join-Path $projectRoot '.tools\packages'
$localSdk = Join-Path $projectRoot '.tools\dotnet\dotnet.exe'
$sdk = if (Test-Path -LiteralPath $localSdk) { $localSdk } else { 'dotnet' }
& $sdk --version
if ($LASTEXITCODE -ne 0) { throw 'No se encuentra el SDK requerido por global.json. Usa el Dev Container o el SDK local; no cambies el target a .NET 9.' }
function Invoke-KronosSdk([string[]]$Arguments) {
    & $sdk @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet fallo: $($Arguments -join ' ')" }
}
if ($Action -eq 'Test') { & (Join-Path $PSScriptRoot 'build.ps1'); return }
Invoke-KronosSdk @('restore','Kronos.sln','--locked-mode')
if ($Action -eq 'Restore') { return }
Invoke-KronosSdk @('build','Kronos.sln','-c','Release','--no-restore')
if ($Action -eq 'Run') { Invoke-KronosSdk @('run','--project','src/Kronos.Desktop','-c','Release','--no-build') }
