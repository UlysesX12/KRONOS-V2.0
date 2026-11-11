# Copyright (c) 2026 Jose Luis Cabanas. Volatility Software License 1.0.
param([Parameter(Mandatory=$true)][string]$Destination, [string]$InstallerPython = 'python')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$Destination = [IO.Path]::GetFullPath($Destination)
$archive = Join-Path $projectRoot '.tools\python-3.14.10-embed-amd64.zip'
$expected = '90905E64A840557D8C1BC4F5B74DB3D7EE85E3FFB217611CAC1C7813ACEA4159'
New-Item -ItemType Directory -Force -Path (Split-Path $archive -Parent) | Out-Null
if (-not (Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.14.10/python-3.14.10-embed-amd64.zip' -OutFile $archive -UseBasicParsing
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expected) { throw 'SHA-256 incorrecto del runtime Python. No se utiliza el paquete.' }
$runtime = Join-Path $Destination 'runtime\python'
New-Item -ItemType Directory -Force -Path $runtime | Out-Null
Expand-Archive -LiteralPath $archive -DestinationPath $runtime -Force
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path $runtime 'python314._pth'), "python314.zip`n.`nLib/site-packages`n", $utf8)
& $InstallerPython -m pip install --only-binary=:all: --require-hashes --no-compile --upgrade --target (Join-Path $runtime 'Lib\site-packages') -r (Join-Path $projectRoot 'engines\memory\requirements.lock')
if ($LASTEXITCODE -ne 0) { throw 'No se pudieron empaquetar las dependencias del motor RAM.' }
& (Join-Path $runtime 'python.exe') -I (Join-Path $projectRoot 'engines\memory\volatility_entry.py') --kronos-version
if ($LASTEXITCODE -ne 0) { throw 'El motor RAM empaquetado no inicia correctamente.' }
Write-Host "Python 3.14.10 y Volatility 2.28.2 incluidos en $runtime"
