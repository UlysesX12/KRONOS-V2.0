param([switch]$Publish, [ValidateSet('win-x64','win-arm64','linux-x64','linux-arm64','osx-x64','osx-arm64')][string]$Runtime = 'win-x64')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $projectRoot
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:AVALONIA_TELEMETRY_OPTOUT = '1'
$env:DOTNET_CLI_HOME = Join-Path $projectRoot '.tools\cli'
$env:NUGET_PACKAGES = Join-Path $projectRoot '.tools\packages'
$dotnetLocal = Join-Path $projectRoot '.tools\dotnet\dotnet.exe'
$sdk = if (Test-Path -LiteralPath $dotnetLocal) { $dotnetLocal } else { 'dotnet' }
function Invoke-Sdk([string[]]$Arguments) {
    & $sdk @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet falló: $($Arguments -join ' ')" }
}
Invoke-Sdk @('restore','Kronos.sln','--locked-mode')
Invoke-Sdk @('build','Kronos.sln','-c','Release','--no-restore')
Invoke-Sdk @('run','--project','tests/Kronos.SmokeTests','-c','Release','--no-build')
Invoke-Sdk @('run','--project','tests/Kronos.DesktopTests','-c','Release','--no-build')
$pythonCmd = if (Get-Command python -ErrorAction SilentlyContinue) { 'python' } else { 'python3' }
& $pythonCmd 'tests/test_legacy.py'
if ($LASTEXITCODE -ne 0) { throw 'Fallaron las pruebas de módulos V1.' }
& $pythonCmd 'tests/test_sync_git.py'
if ($LASTEXITCODE -ne 0) { throw 'Fallaron las pruebas de sincronizacion Git.' }
if ($Publish) {
    $target = Join-Path $projectRoot "artifacts/$Runtime"
    Invoke-Sdk @('publish','src/Kronos.Desktop','-c','Release','-r',$Runtime,'--self-contained','true','-o',$target,'-p:PublishReadyToRun=false',"-p:NuGetLockFilePath=packages.$Runtime.lock.json")
    Copy-Item -LiteralPath 'README.md','AUTHORS.md','LICENSE.md','docs/THIRD_PARTY_NOTICES.md' -Destination $target
    Copy-Item -LiteralPath 'docs' -Destination $target -Recurse -Force
    Copy-Item -LiteralPath 'vendor/PROVENANCE.md','vendor/PROVENANCE_SHA256.csv' -Destination (Join-Path $target 'vendor')
    $licenses = Join-Path $target 'licenses'
    New-Item -ItemType Directory -Force -Path $licenses | Out-Null
    Get-ChildItem -LiteralPath $env:NUGET_PACKAGES -Recurse -File | Where-Object { $_.Name -match '^(LICENSE|COPYING|THIRD.PARTY.NOTICES)' } | ForEach-Object {
        $relativeName = $_.FullName.Substring($env:NUGET_PACKAGES.Length + 1).Replace('\','_').Replace('/','_')
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $licenses $relativeName)
    }
    Get-ChildItem -LiteralPath $target -Recurse -File | Where-Object { $_.Name -ne 'PACKAGE_SHA256.csv' } | ForEach-Object {
        [pscustomobject]@{ File=$_.FullName.Substring($target.Length+1); SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    } | Export-Csv -LiteralPath (Join-Path $target 'PACKAGE_SHA256.csv') -Encoding UTF8 -NoTypeInformation
    Write-Host "Publicación preparada en $target"
}
