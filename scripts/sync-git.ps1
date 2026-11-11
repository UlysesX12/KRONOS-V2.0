# Copyright (c) 2026 Jose Luis Cabanas (JLC / UlysesX12). See LICENSE.md.
# Sincroniza exclusivamente el repositorio inicial sin commits. No elimina archivos.
param()
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $projectRoot
$expectedRemote = 'https://github.com/UlysesX12/KRONOS-V2.0.git'
function Invoke-KronosGit([string[]]$Arguments) {
    $result = & git @Arguments
    if ($LASTEXITCODE -ne 0) { throw "git fallo: $($Arguments -join ' '). No se han eliminado archivos." }
    return $result
}
$actualRoot = Invoke-KronosGit @('rev-parse','--show-toplevel')
if ([IO.Path]::GetFullPath($actualRoot) -ne [IO.Path]::GetFullPath($projectRoot)) { throw 'La raiz Git no corresponde al proyecto.' }
$null = & git rev-parse --verify --quiet HEAD
if ($LASTEXITCODE -eq 0) {
    Write-Host 'El repositorio ya tiene commits. No se modifica su historial ni sus cambios pendientes.'
    Invoke-KronosGit @('status','--short')
    return
}
$remotes = @(Invoke-KronosGit @('remote'))
if ($remotes -contains 'origin') {
    $url = Invoke-KronosGit @('remote','get-url','origin')
    if ($url -ne $expectedRemote) { throw "El remoto origin no corresponde a KRONOS: $url" }
} else { $null = Invoke-KronosGit @('remote','add','origin',$expectedRemote) }
$null = Invoke-KronosGit @('fetch','origin','main')
$paths = @(Invoke-KronosGit @('-c','core.quotepath=false','ls-tree','-r','--name-only','origin/main'))
$differences = @()
foreach ($relative in $paths) {
    $file = [IO.Path]::GetFullPath((Join-Path $projectRoot $relative))
    if (-not $file.StartsWith($projectRoot.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Ruta remota fuera del proyecto.' }
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { $differences += $relative; continue }
    $expected = Invoke-KronosGit @('rev-parse',"origin/main:$relative")
    $actual = Invoke-KronosGit @('hash-object','--path',$relative,'--',$relative)
    if ($actual -ne $expected) { $differences += $relative }
}
if ($differences.Count -gt 0) { throw "Los archivos locales difieren de GitHub. Se conserva todo sin cambiar HEAD ni el indice: $($differences -join ', ')" }
# Solo tras verificar igualdad, establecer HEAD e indice. --mixed conserva el arbol de trabajo.
$null = Invoke-KronosGit @('reset','--mixed','origin/main')
$null = Invoke-KronosGit @('branch','--set-upstream-to=origin/main')
Write-Host 'Historial sincronizado con GitHub. Los archivos locales se han conservado.'
Invoke-KronosGit @('status','--short')
