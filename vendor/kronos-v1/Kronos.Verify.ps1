<#
kronos Version 1.0 by JLC
Copyright (c) 2026 JLC. Todos los derechos reservados.
Verificación independiente de un caso Kronos. No requiere privilegios de administrador.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$CaseFolder
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $CaseFolder -ErrorAction Stop).ProviderPath)
$rootPrefix = $root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
$manifestPath = Join-Path $root 'MANIFEST_HASHES_SHA256.csv'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "No se encontró el manifiesto en $root"
}

$rows = @(Import-Csv -LiteralPath $manifestPath -Encoding UTF8)
if ($rows.Count -eq 0) { throw 'El manifiesto está vacío.' }

$errorsFound = New-Object 'System.Collections.Generic.List[string]'
$seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($row in $rows) {
    $relative = [string]$row.RutaRelativa
    if ([string]::IsNullOrWhiteSpace($relative) -or [IO.Path]::IsPathRooted($relative)) {
        $errorsFound.Add("Ruta relativa inválida: $relative")
        continue
    }
    try { $target = [IO.Path]::GetFullPath((Join-Path $root $relative)) }
    catch {
        $errorsFound.Add("Ruta inválida: $relative")
        continue
    }
    if (-not $target.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        $errorsFound.Add("Ruta fuera del caso: $relative")
        continue
    }
    if (-not $seen.Add($relative)) {
        $errorsFound.Add("Ruta duplicada en el manifiesto: $relative")
        continue
    }
    if ($row.Hash_SHA256 -notmatch '^[0-9a-fA-F]{64}$') {
        $errorsFound.Add("Hash inválido: $relative")
        continue
    }
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
        $errorsFound.Add("Archivo ausente: $relative")
        continue
    }
    $file = Get-Item -LiteralPath $target
    if ([string]$file.Length -ne [string]$row.TamanoBytes) {
        $errorsFound.Add("Tamaño diferente: $relative")
    }
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $target).Hash
    if ($actualHash -ne $row.Hash_SHA256) {
        $errorsFound.Add("SHA-256 diferente: $relative")
    }
}

foreach ($file in (Get-ChildItem -LiteralPath $root -Recurse -File)) {
    if ($file.FullName -eq $manifestPath) { continue }
    $relative = $file.FullName.Substring($rootPrefix.Length)
    if (-not $seen.Contains($relative)) {
        $errorsFound.Add("Archivo fuera del manifiesto: $relative")
    }
}

if ($errorsFound.Count -gt 0) {
    throw "Verificación fallida ($($errorsFound.Count) incidencias):`n$($errorsFound -join "`n")"
}

[PSCustomObject]@{
    Caso = $root
    ArchivosVerificados = $rows.Count
    Estado = 'INTEGRO'
    VerificadoUTC = (Get-Date).ToUniversalTime().ToString('o')
}
