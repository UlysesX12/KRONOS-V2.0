param([switch]$Publish, [ValidateSet('win-x64','win-arm64','linux-x64','linux-arm64','osx-x64','osx-arm64')][string]$Runtime = 'win-x64')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $projectRoot
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:AVALONIA_TELEMETRY_OPTOUT = '1'
$env:DOTNET_CLI_HOME = Join-Path $projectRoot '.tools\cli'
$env:NUGET_PACKAGES = Join-Path $projectRoot '.tools\packages'
$sdk = 'dotnet'
function Invoke-Sdk([string[]]$Arguments) {
    & $sdk @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet falló: $($Arguments -join ' ')" }
}
Invoke-Sdk @('restore','Kronos.sln','--locked-mode')
Invoke-Sdk @('build','Kronos.sln','-c','Release','--no-restore')
Invoke-Sdk @('run','--project','tests/Kronos.SmokeTests','-c','Release','--no-build')
Invoke-Sdk @('run','--project','tests/Kronos.DesktopTests','-c','Release','--no-build')
$pythonCmd = if (Get-Command python -ErrorAction SilentlyContinue) { 'python' } else { 'python3' }
& $pythonCmd 'engines/memory/setup_engine.py' --target '.tools/memory'
if ($LASTEXITCODE -ne 0) { throw 'No se pudo preparar el motor RAM aislado.' }
Invoke-Sdk @('run','--project','tests/Kronos.MemoryTests','-c','Release','--no-build','--','--real-engine')
& $pythonCmd 'tests/test_legacy.py'
if ($LASTEXITCODE -ne 0) { throw 'Fallaron las pruebas de módulos V1.' }
& $pythonCmd 'tests/test_sync_git.py'
if ($LASTEXITCODE -ne 0) { throw 'Fallaron las pruebas de sincronizacion Git.' }
if ($Publish) {
    $target = Join-Path $projectRoot "artifacts/$Runtime"
    Invoke-Sdk @('publish','src/Kronos.Desktop','-c','Release','-r',$Runtime,'--self-contained','true','-o',$target,'-p:PublishReadyToRun=false',"-p:NuGetLockFilePath=packages.$Runtime.lock.json")
    foreach ($obsolete in @('vendor/kronos-v1/KRONOS_GUIA_FACIL.txt','vendor/kronos-v1/KRONOS_USB_SHA256_20261020_195425_578.csv')) {
        $obsoletePath = [IO.Path]::GetFullPath((Join-Path $target $obsolete))
        if (-not $obsoletePath.StartsWith($target.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Ruta de limpieza fuera de la publicacion.' }
        if (Test-Path -LiteralPath $obsoletePath -PathType Leaf) { Remove-Item -LiteralPath $obsoletePath }
    }
    Copy-Item -LiteralPath 'README.md','AUTHORS.md','LICENSE.md','docs/THIRD_PARTY_NOTICES.md' -Destination $target
    Copy-Item -LiteralPath 'docs' -Destination $target -Recurse -Force
    Copy-Item -LiteralPath 'licenses' -Destination $target -Recurse -Force
    Copy-Item -LiteralPath 'vendor/PROVENANCE.md','vendor/PROVENANCE_SHA256.csv' -Destination (Join-Path $target 'vendor')
    $licenses = Join-Path $target 'licenses'
    New-Item -ItemType Directory -Force -Path $licenses | Out-Null
    Get-ChildItem -LiteralPath $env:NUGET_PACKAGES -Recurse -File | Where-Object { $_.Name -match '^(LICENSE|COPYING|THIRD.PARTY.NOTICES)' } | ForEach-Object {
        $relativeName = $_.FullName.Substring($env:NUGET_PACKAGES.Length + 1).Replace('\','_').Replace('/','_')
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $licenses $relativeName)
    }
    if ($Runtime -eq 'win-x64') { & (Join-Path $PSScriptRoot 'package-memory.ps1') -Destination $target -InstallerPython $pythonCmd }
    Get-ChildItem -LiteralPath $target -Recurse -File | Where-Object { $_.Name -ne 'PACKAGE_SHA256.csv' } | ForEach-Object {
        [pscustomobject]@{ File=$_.FullName.Substring($target.Length+1); SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    } | Export-Csv -LiteralPath (Join-Path $target 'PACKAGE_SHA256.csv') -Encoding UTF8 -NoTypeInformation
    if ($Runtime -eq 'win-x64' -and $env:OS -eq 'Windows_NT') {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut((Join-Path $projectRoot 'KRONOS.lnk'))
        $shortcut.TargetPath = Join-Path $target 'Kronos.Desktop.exe'
        $shortcut.WorkingDirectory = $target
        $shortcut.Description = 'Abrir KRONOS. No requiere VS Code ni Docker.'
        $shortcut.IconLocation = $shortcut.TargetPath
        $shortcut.Save()
    }
    Write-Host "Publicación preparada en $target"
}
