<#
================================================================================
  KRONOS
  kronos Version 1.0 by JLC
  Kit de Recolección, Organización y Normalización de Observaciones de Seguridad
  Copyright (c) 2026 JLC. Todos los derechos reservados.
  Objetivo: triage en vivo de artefactos Windows con registro de errores y hashes.
================================================================================
#>

param(
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$WinPmemExpectedSha256,
    [ValidatePattern('^[A-Za-z0-9_-]{1,64}$')]
    [string]$CaseId = 'SIN_ID',
    [string]$Operator = [Environment]::UserName,
    [string]$OutputRoot,
    [ValidateSet('Triage', 'Extended')]
    [string]$CollectionProfile = 'Triage',
    [ValidateRange(100, 100000)]
    [int]$SecurityEventLimit = 10000,
    [ValidateRange(100, 100000)]
    [int]$SysmonEventLimit = 10000,
    [string]$BrowserPythonPath,
    [ValidateRange(1, 200000)]
    [int]$BrowserRowLimit = 20000,
    [ValidateSet('Ask', 'Acquire', 'Skip')]
    [string]$MemoryMode = 'Ask'
)

# Mantener las tildes al mostrar o redirigir la salida en Windows PowerShell 5.1.
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try { [Console]::OutputEncoding = $OutputEncoding } catch { }

# 0. CONTROL DE PRIVILEGIOS DE ADMINISTRADOR
$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "`n [!] ACCESO DENEGADO: kronos Version 1.0 requiere elevación administrativa.`n" -ForegroundColor Red
    Exit 1
}

$ErrorActionPreference = 'Stop'
$StartedUtc = (Get-Date).ToUniversalTime()
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss_fff"
$RootDrive = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $RootDrive) {$RootDrive = (Get-Location).Path }
if (-not $OutputRoot) { $OutputRoot = $RootDrive }
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)

# Estructura del caso dentro del almacenamiento forense
$CaseFolder = Join-Path $OutputRoot "KRONOS_CASE_$($CaseId)_$Timestamp"
$EvidenceRaw = Join-Path $CaseFolder "RawArtifacts"
$ToolsFolder = Join-Path $RootDrive "tools"

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
New-Item -ItemType Directory -Path $EvidenceRaw -Force | Out-Null
New-Item -ItemType Directory -Path $ToolsFolder -Force | Out-Null
$script:CollectionIssues = @()
$script:ArtifactSources = @()
$script:CaseMetadata = [ordered]@{
    Tool = 'kronos Version 1.0 by JLC'
    ToolFullName = 'Kit de Recolección, Organización y Normalización de Observaciones de Seguridad'
    ToolSHA256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash
    CaseId = $CaseId
    OperatorDeclared = $Operator
    Profile = $CollectionProfile
    SecurityEventLimit = $SecurityEventLimit
    SysmonEventLimit = $SysmonEventLimit
    SysmonAvailable = $null
    BrowserRowLimit = $BrowserRowLimit
    BrowserAnalysis = 'SKIPPED'
    MemoryMode = $MemoryMode
    Hostname = $env:COMPUTERNAME
    StartedUTC = $StartedUtc.ToString('o')
    FinishedUTC = $null
    Status = 'IN_PROGRESS'
    Issues = 0
}
$MetadataFile = Join-Path $CaseFolder 'CASE_METADATA.json'
$script:CaseMetadata | ConvertTo-Json -Depth 4 | Out-File -LiteralPath $MetadataFile -Encoding UTF8

function Register-KronosArtifact([string]$Source, [string]$Destination, [string]$Method) {
    $sourceItem = Get-Item -LiteralPath $Source -ErrorAction SilentlyContinue
    $script:ArtifactSources += [PSCustomObject]@{
        CapturedUTC = (Get-Date).ToUniversalTime().ToString('o')
        Source = $Source
        SourceLastWriteUTC = if ($sourceItem) { $sourceItem.LastWriteTimeUtc.ToString('o') } else { $null }
        RelativePath = $Destination.Substring($CaseFolder.Length + 1)
        Method = $Method
    }
}

function Add-KronosIssue([string]$Stage, [string]$Message) {
    $script:CollectionIssues += [PSCustomObject]@{
        Fecha = (Get-Date).ToUniversalTime().ToString('o')
        Etapa = $Stage
        Error = $Message
    }
    Write-Warning "[$Stage] $Message"
}

function Get-KronosEvents([hashtable]$Filter, [int]$Maximum = 500) {
    try {
        Get-WinEvent -FilterHashtable $Filter -MaxEvents $Maximum -ErrorAction Stop
    } catch {
        if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') {
            Add-KronosIssue 'Eventos' "$($Filter.LogName)/$($Filter.Id): $($_.Exception.Message)"
        }
    }
}

function Get-KronosEventValue($Event, [string]$Name) {
    try {
        $xml = [xml]$Event.ToXml()
        foreach ($node in $xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")) {
            if ($node.GetAttribute('Name') -eq $Name) { return $node.InnerText }
        }
    } catch {
        Add-KronosIssue 'Eventos' "No se pudo interpretar el evento $($Event.Id): $($_.Exception.Message)"
    }
    return $null
}

function Convert-KronosSecurityEvent($Event) {
    $xml = [xml]$Event.ToXml()
    $data = @{}
    foreach ($node in $xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")) {
        $name = $node.GetAttribute('Name')
        if ($name) { $data[$name] = $node.InnerText }
    }
    $id = [int]$Event.Id
    $kind = switch ($id) {
        4624 { 'Inicio de sesión' }
        4625 { 'Inicio de sesión fallido' }
        4634 { 'Fin de sesión' }
        4647 { 'Cierre iniciado por usuario' }
        4648 { 'Credenciales explícitas' }
        4657 { 'Valor de registro modificado' }
        4663 { 'Acceso a objeto auditado' }
        4688 { 'Proceso creado' }
        4698 { 'Tarea programada creada' }
        4702 { 'Tarea programada actualizada' }
        default { 'Evento de seguridad' }
    }
    $isLogon = $id -in @(4624, 4625, 4634)
    [PSCustomObject]@{
        FechaUTC = $Event.TimeCreated.ToUniversalTime().ToString('o')
        EventoID = $id
        Accion = $kind
        Usuario = if ($isLogon) { $data['TargetUserName'] } else { $data['SubjectUserName'] }
        Dominio = if ($isLogon) { $data['TargetDomainName'] } else { $data['SubjectDomainName'] }
        SID = if ($isLogon) { $data['TargetUserSid'] } else { $data['SubjectUserSid'] }
        LogonID = if ($isLogon) { $data['TargetLogonId'] } else { $data['SubjectLogonId'] }
        TipoInicio = $data['LogonType']
        IPOrigen = $data['IpAddress']
        EquipoOrigen = $data['WorkstationName']
        CuentaDestino = $data['TargetUserName']
        SesionDestino = $data['TargetLogonId']
        Proceso = if ($id -eq 4688) { $data['NewProcessName'] } else { $data['ProcessName'] }
        PID = $data['NewProcessId']
        ProcesoPadre = $data['ParentProcessName']
        PIDPadre = $data['ProcessId']
        Comando = $data['CommandLine']
        Objeto = $data['ObjectName']
        Valor = $data['ObjectValueName']
        NuevoValor = $data['NewValue']
        Acceso = $data['AccessList']
        Tarea = $data['TaskName']
        RegistroID = [string]$Event.RecordId
    }
}

function Convert-KronosSysmonEvent($Event) {
    $xml = [xml]$Event.ToXml()
    $data = @{}
    foreach ($node in $xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")) {
        $name = $node.GetAttribute('Name')
        if ($name) { $data[$name] = $node.InnerText }
    }
    $id = [int]$Event.Id
    $kind = switch ($id) {
        1 { 'Proceso creado' }
        3 { 'Conexión de red' }
        11 { 'Archivo creado' }
        12 { 'Objeto de registro creado/eliminado' }
        13 { 'Valor de registro establecido' }
        14 { 'Objeto de registro renombrado' }
        22 { 'Consulta DNS' }
        23 { 'Archivo eliminado y archivado' }
        26 { 'Archivo eliminado' }
        default { 'Evento Sysmon' }
    }
    [PSCustomObject]@{
        FechaUTC = $Event.TimeCreated.ToUniversalTime().ToString('o')
        EventoID = $id
        Accion = $kind
        Usuario = $data['User']
        ProcessGuid = $data['ProcessGuid']
        ParentProcessGuid = $data['ParentProcessGuid']
        Proceso = $data['Image']
        Comando = $data['CommandLine']
        IPOrigen = $data['SourceIp']
        IPDestino = $data['DestinationIp']
        PuertoDestino = $data['DestinationPort']
        HostDestino = $data['DestinationHostname']
        ConsultaDNS = $data['QueryName']
        Archivo = $data['TargetFilename']
        ObjetoRegistro = $data['TargetObject']
        ValorRegistro = $data['Details']
        RegistroID = [string]$Event.RecordId
    }
}

function Invoke-KronosCollection([string]$Stage, [scriptblock]$Action) {
    try { & $Action }
    catch { Add-KronosIssue $Stage $_.Exception.Message }
}

function Export-KronosCsv([object[]]$Rows, [string]$Path) {
    $safeRows = foreach ($row in $Rows) {
        $fields = [ordered]@{}
        foreach ($property in $row.PSObject.Properties) {
            $value = [string]$property.Value
            if ($value -match '^\s*[=+@-]') { $value = "'$value" }
            $fields[$property.Name] = $value
        }
        [PSCustomObject]$fields
    }
    $safeRows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}

$TranscriptFile = Join-Path $CaseFolder 'SESSION_TRANSCRIPT.txt'
$TranscriptStarted = $false
try {
    Start-Transcript -LiteralPath $TranscriptFile -IncludeInvocationHeader -ErrorAction Stop | Out-Null
    $TranscriptStarted = $true
} catch {
    Add-KronosIssue 'Transcripción' $_.Exception.Message
}

Clear-Host
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "   ██╗  ██╗██████╗  ██████╗ ███╗   ██╗ ██████╗ ███████╗" -ForegroundColor Cyan
Write-Host "   ██║ ██╔╝██╔══██╗██╔═══██╗████╗  ██║██╔═══██╗██╔════╝" -ForegroundColor Cyan
Write-Host "   █████╔╝ ██████╔╝██║   ██║██╔██╗ ██║██║   ██║███████╗" -ForegroundColor White
Write-Host "   ██╔═██╗ ██╔══██╗██║   ██║██║╚██╗██║██║   ██║╚════██║" -ForegroundColor White
Write-Host "   ██║  ██╗██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝███████║" -ForegroundColor DarkCyan
Write-Host "   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝" -ForegroundColor DarkCyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " Kit de Recolección, Organización y Normalización de Observaciones de Seguridad" -ForegroundColor Cyan
Write-Host " kronos Version 1.0 by JLC - TRIAGE FORENSE Y DETECCIÓN ANTIFORENSE" -ForegroundColor Yellow
Write-Host " Copyright (c) 2026 JLC. Todos los derechos reservados." -ForegroundColor Gray
Write-Host " Destino de preservación: $CaseFolder" -ForegroundColor Gray
Write-Host "================================================================================`n" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# 1. EVALUACIÓN PREVIA DE SEGURIDAD DEL KERNEL (VBS / HVCI)
# ------------------------------------------------------------------------------
Write-Host "[*] Comprobando integridad de memoria y aislamiento de núcleos (HVCI)..." -ForegroundColor Gray
$DeviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
if ($null -eq $DeviceGuard) {
    $VbsRunning = 'No disponible'
    $HvciRunning = 'No disponible'
    Add-KronosIssue 'DeviceGuard' 'No se pudo consultar Win32_DeviceGuard.'
} else {
    $VbsRunning = $DeviceGuard.VirtualizationBasedSecurityStatus -eq 2
    $HvciRunning = 2 -in @($DeviceGuard.SecurityServicesRunning)
}

Write-Host " [*] VBS activo: $VbsRunning | Integridad de memoria (HVCI) activa: $HvciRunning" -ForegroundColor Gray

# ------------------------------------------------------------------------------
# 2. ADQUISICIÓN INTERACTIVA DE MEMORIA FÍSICA
# ------------------------------------------------------------------------------
$WinPmem = Join-Path $ToolsFolder "winpmem_mini_x64.exe"
$DumpRAM = switch ($MemoryMode) {
    'Acquire' { 'S' }
    'Skip' { 'N' }
    default { Read-Host "`n [?] ¿Deseas adquirir la memoria RAM completa para Volatility? (S/N)" }
}
if ($DumpRAM -match '^[sS]$') {
    $RamTarget = Join-Path $CaseFolder "MEMORY_RAW_$Timestamp.raw"
    if (-not (Test-Path -LiteralPath $WinPmem)) {
        Add-KronosIssue 'Memoria' "No se encontró $WinPmem. Se omite la captura de RAM."
    } else {
        try {
            $signature = Get-AuthenticodeSignature -LiteralPath $WinPmem
            $toolHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $WinPmem).Hash
            $trustedTool = $signature.Status -eq 'Valid'
            if ($WinPmemExpectedSha256) {
                $trustedTool = $toolHash -eq $WinPmemExpectedSha256
            }
            if (-not $trustedTool) {
                Add-KronosIssue 'Memoria' "Validación de WinPmem fallida. Firma: $($signature.Status). SHA-256: $toolHash"
            } else {
                "$toolHash  winpmem_mini_x64.exe" | Out-File -LiteralPath (Join-Path $CaseFolder 'WINPMEM_TOOL_SHA256.txt') -Encoding UTF8
                Write-Host " [*] Adquiriendo memoria física mediante WinPmem..." -ForegroundColor Magenta
                $memoryProcess = Start-Process -FilePath $WinPmem -ArgumentList "`"$RamTarget`"" -Wait -NoNewWindow -PassThru -ErrorAction Stop
                if ($memoryProcess.ExitCode -ne 0) {
                    throw "WinPmem terminó con código $($memoryProcess.ExitCode)."
                }
                if (-not (Test-Path -LiteralPath $RamTarget) -or (Get-Item -LiteralPath $RamTarget).Length -eq 0) {
                    throw "WinPmem no creó una imagen de memoria válida."
                }
                $RHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $RamTarget).Hash
                "$RHash  MEMORY_RAW_$Timestamp.raw" | Out-File -LiteralPath (Join-Path $CaseFolder "RAM_HASH_SHA256.txt") -Encoding UTF8
                Register-KronosArtifact 'MEMORIA_FISICA' $RamTarget 'WinPmem mini'
                Write-Host "     [+] Volcado completado y hash SHA-256 calculado." -ForegroundColor Green
            }
        } catch {
            Add-KronosIssue 'Memoria' "Falló la adquisición de RAM: $($_.Exception.Message)"
        }
    }
}

# ------------------------------------------------------------------------------
# 3. DETECCIÓN DE ANTI-FORENSICS (BORRADO DE LOGS DE EVENTOS)
# ------------------------------------------------------------------------------
Write-Host "`n[*] Verificando intentos de evasión y borrado de registros..." -ForegroundColor Cyan
$AntiForensicEvents = @()

# Event ID 1102: Log de Seguridad vaciado
$SecurityClear = Get-KronosEvents @{LogName='Security'; Id=1102} | ForEach-Object {
    [PSCustomObject]@{
        FechaUTC = $_.TimeCreated.ToUniversalTime().ToString('o')
        Evento   = "Log de Seguridad VACIADO (ID 1102)"
        Usuario  = Get-KronosEventValue $_ 'SubjectUserName'
        Dominio  = Get-KronosEventValue $_ 'SubjectDomainName'
        Detalles = "Evento de vaciado del registro de Seguridad; revisar el contexto."
    }
}
if ($SecurityClear) { $AntiForensicEvents += $SecurityClear }

# Event ID 104: Log de Sistema vaciado
$SystemClear = Get-KronosEvents @{LogName='System'; Id=104} | ForEach-Object {
    [PSCustomObject]@{
        FechaUTC = $_.TimeCreated.ToUniversalTime().ToString('o')
        Evento   = "Log de Sistema VACIADO (ID 104)"
        Usuario  = [string]$_.UserId
        Dominio  = 'N/D'
        Detalles = "Evento de vaciado del registro del Sistema; revisar el contexto."
    }
}
if ($SystemClear) { $AntiForensicEvents += $SystemClear }

if ($AntiForensicEvents.Count -gt 0) {
    Write-Host " [!] Se han observado eventos de vaciado de registros; revisar su contexto." -ForegroundColor Yellow
} else {
    Write-Host " [+] No se observaron eventos de vaciado en los registros consultados." -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 4. EXTRACCIÓN DE NAVEGACIÓN WEB (CHROME, EDGE, BRAVE)
# ------------------------------------------------------------------------------
Write-Host "`n[*] Preservando bases de datos de historial y descargas de navegadores..." -ForegroundColor Cyan
$BrowserArtifacts = @()
$BrowserProfiles = @(
    @{ Name="Google Chrome"; Path="AppData\Local\Google\Chrome\User Data" },
    @{ Name="Microsoft Edge"; Path="AppData\Local\Microsoft\Edge\User Data" },
    @{ Name="Brave Browser"; Path="AppData\Local\BraveSoftware\Brave-Browser\User Data" }
)

$UsersRoot = Join-Path $env:SystemDrive 'Users'
Get-ChildItem -LiteralPath $UsersRoot -Directory | ForEach-Object {
    $userDir = $_.FullName
    $userName = $_.Name

    foreach ($b in $BrowserProfiles) {
        $browserRoot = Join-Path $userDir $b.Path
        if (-not (Test-Path -LiteralPath $browserRoot)) { continue }
        try { $profiles = @(Get-ChildItem -LiteralPath $browserRoot -Directory -ErrorAction Stop) }
        catch {
            Add-KronosIssue 'Navegadores' "$browserRoot : $($_.Exception.Message)"
            continue
        }
        foreach ($profile in $profiles) {
            $historyFile = Join-Path $profile.FullName 'History'
            if (-not (Test-Path -LiteralPath $historyFile)) { continue }
            $destDir = Join-Path $EvidenceRaw "Browsers\$userName\$($b.Name)\$($profile.Name)"
            try {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                $fileInfo = Get-Item -LiteralPath $historyFile
                $destFile = Join-Path $destDir 'History'
                Copy-Item -LiteralPath $historyFile -Destination $destFile -ErrorAction Stop
                Register-KronosArtifact $historyFile $destFile 'Copy-Item'
                $companions = @()
                foreach ($suffix in @('-wal', '-shm')) {
                    $sidecar = "$historyFile$suffix"
                    if (Test-Path -LiteralPath $sidecar) {
                        $sidecarDestination = Join-Path $destDir "History$suffix"
                        Copy-Item -LiteralPath $sidecar -Destination $sidecarDestination -ErrorAction Stop
                        Register-KronosArtifact $sidecar $sidecarDestination 'Copy-Item'
                        $companions += "History$suffix"
                    }
                }
                $BrowserArtifacts += [PSCustomObject]@{
                    Usuario = $userName
                    Navegador = $b.Name
                    Perfil = $profile.Name
                    FechaModificacion = $fileInfo.LastWriteTimeUtc.ToString('o')
                    TamanoBytes = $fileInfo.Length
                    ArchivoCopia = $destFile.Substring($CaseFolder.Length + 1)
                    ArchivosAsociados = ($companions -join ', ')
                }
            } catch {
                Add-KronosIssue 'Navegadores' "$historyFile : $($_.Exception.Message)"
            }
        }
    }
}
Write-Host " [+] Bases de datos de navegación preservadas: $($BrowserArtifacts.Count)" -ForegroundColor Green

$BrowserVisits = @()
$BrowserDownloads = @()
if ($BrowserPythonPath) {
    try {
        $pythonItem = Get-Item -LiteralPath $BrowserPythonPath -ErrorAction Stop
        if ($pythonItem.PSIsContainer) { throw 'La ruta de Python debe señalar un ejecutable.' }
        $browserAnalyzer = Join-Path $RootDrive 'Kronos.Browser.py'
        if (-not (Test-Path -LiteralPath $browserAnalyzer -PathType Leaf)) { throw "No se encontró $browserAnalyzer" }
        $script:CaseMetadata['BrowserPythonSHA256'] = (Get-FileHash -LiteralPath $pythonItem.FullName -Algorithm SHA256).Hash
        $script:CaseMetadata['BrowserAnalyzerSHA256'] = (Get-FileHash -LiteralPath $browserAnalyzer -Algorithm SHA256).Hash
        Write-Host " [*] Analizando visitas y descargas de las copias de navegador..." -ForegroundColor Cyan
        $browserOutput = & $pythonItem.FullName $browserAnalyzer --case-folder $CaseFolder --limit $BrowserRowLimit 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Analizador finalizó con código $LASTEXITCODE : $browserOutput" }
        $analysis = Get-Content -LiteralPath (Join-Path $CaseFolder 'BrowserAnalysis.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $script:CaseMetadata['BrowserAnalysis'] = $analysis.Status
        $BrowserVisits = @(Import-Csv -LiteralPath (Join-Path $CaseFolder 'BrowserVisits.csv') -Encoding UTF8)
        $BrowserDownloads = @(Import-Csv -LiteralPath (Join-Path $CaseFolder 'BrowserDownloads.csv') -Encoding UTF8)
        foreach ($issue in $analysis.Issues) { Add-KronosIssue 'Navegadores' $issue }
        Write-Host " [+] Visitas: $($BrowserVisits.Count); descargas: $($BrowserDownloads.Count)." -ForegroundColor Green
    } catch {
        $script:CaseMetadata['BrowserAnalysis'] = 'FAILED'
        Add-KronosIssue 'Navegadores' "No se pudo analizar History: $($_.Exception.Message)"
    }
}

# ------------------------------------------------------------------------------
# 5. TRIAGE DE ACCESOS, SOCKETS, BÚSQUEDAS Y PERSISTENCIAS
# ------------------------------------------------------------------------------
Write-Host "`n[*] Extrayendo artefactos de sistema, red y ejecución en vivo..." -ForegroundColor Cyan

# 5.1 Accesos RDP / Red (Event ID 4624)
$Logons = Get-KronosEvents @{LogName='Security'; Id=4624} | ForEach-Object {
    $logonType = Get-KronosEventValue $_ 'LogonType'
    if ($logonType -in @('3', '10')) {
        [PSCustomObject]@{
            FechaUTC = $_.TimeCreated.ToUniversalTime().ToString('o')
            Usuario = Get-KronosEventValue $_ 'TargetUserName'
            Tipo = if ($logonType -eq '10') { 'RDP (Escritorio Remoto)' } else { 'Red (SMB/RPC)' }
            IP_Origen = Get-KronosEventValue $_ 'IpAddress'
            Host_Remoto = Get-KronosEventValue $_ 'WorkstationName'
            LogonID = Get-KronosEventValue $_ 'TargetLogonId'
        }
    }
}

# 5.2 Sockets y hashes SHA-256 de los ejecutables asociados
$HashCache = @{}
try {
    $NetworkSockets = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -in @('Established', 'Listen') } | ForEach-Object {
        $connection = $_
        $proc = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
        $pPath = $proc.Path
        $hash = 'N/D'
        if ($pPath -and (Test-Path -LiteralPath $pPath)) {
            if (-not $HashCache.ContainsKey($pPath)) {
                try { $HashCache[$pPath] = (Get-FileHash -Algorithm SHA256 -LiteralPath $pPath -ErrorAction Stop).Hash }
                catch { $HashCache[$pPath] = 'No accesible' }
            }
            $hash = $HashCache[$pPath]
        }
        [PSCustomObject]@{
            Protocolo = 'TCP'
            Local = "$($connection.LocalAddress):$($connection.LocalPort)"
            Remota = "$($connection.RemoteAddress):$($connection.RemotePort)"
            Estado = $connection.State
            PID = $connection.OwningProcess
            Proceso = $proc.ProcessName
            Ruta = $pPath
            SHA256_Ejecutable = $hash
        }
    })
} catch {
    $NetworkSockets = @()
    Add-KronosIssue 'Red' $_.Exception.Message
}

# 5.3 Búsquedas en Explorador de Windows (WordWheelQuery)
$Searches = foreach ($u in (Get-ChildItem "Registry::HKEY_USERS" | Where-Object { $_.Name -match 'S-1-5-21-' -and $_.Name -notmatch '_Classes' })) {
    $sid = $u.PSChildName
    $path = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
    if (Test-Path $path) {
        $props = Get-ItemProperty $path
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -match '^\d+$') {
                [PSCustomObject]@{
                    SID_Usuario = $sid
                    Termino     = [System.Text.Encoding]::Unicode.GetString($p.Value).TrimEnd("`0")
                }
            }
        }
    }
}

# 5.4 Archivos LNK Recientes y Prefetch
$RecentDocs = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*.lnk" -ErrorAction SilentlyContinue | 
    Sort-Object LastWriteTime -Descending | Select-Object -First 50 | ForEach-Object {
        [PSCustomObject]@{
            Usuario      = $_.FullName.Split('\')[2]
            Archivo      = $_.Name.Replace('.lnk','')
            FechaModificacion = $_.LastWriteTimeUtc.ToString('o')
        }
    }

$Prefetch = if (Test-Path "$env:SystemRoot\Prefetch") {
    Get-ChildItem -Path "$env:SystemRoot\Prefetch\*.pf" | Sort-Object LastWriteTime -Descending | Select-Object -First 50 | ForEach-Object {
        [PSCustomObject]@{
            Binario         = $_.Name
            FechaModificacion = $_.LastWriteTimeUtc.ToString('o')
            TamanoBytes     = $_.Length
        }
    }
} else { @() }

# 5.5 JumpLists (copia cruda)
$JumpListDir = Join-Path $EvidenceRaw "JumpLists"
New-Item -ItemType Directory -Path $JumpListDir -Force | Out-Null
Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms" -ErrorAction SilentlyContinue | ForEach-Object {
    $jumpFile = $_
    $userName = $jumpFile.FullName.Split('\')[2]
    $userJumpDir = Join-Path $JumpListDir $userName
    try {
        New-Item -ItemType Directory -Path $userJumpDir -Force | Out-Null
        Copy-Item -LiteralPath $jumpFile.FullName -Destination $userJumpDir -ErrorAction Stop
        Register-KronosArtifact $jumpFile.FullName (Join-Path $userJumpDir $jumpFile.Name) 'Copy-Item'
    } catch {
        Add-KronosIssue 'JumpLists' "$($jumpFile.FullName): $($_.Exception.Message)"
    }
}

# 5.6 Dispositivos USB
$USBDevices = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction SilentlyContinue | Select-Object `
    FriendlyName, HardwareID, @{N="NumeroSerie";E={$_.PSChildName}}

# 5.7 Inventario ampliado y exportación EVTX. El perfil Triage evita este coste.
$Processes = @()
$Services = @()
$ScheduledTasks = @()
$StartupEntries = @()
$LocalUsers = @()
$DefenderStatus = @()
$FirewallProfiles = @()
$LogExports = @()
$SecurityEvents = @()
$SysmonEvents = @()

if ($CollectionProfile -eq 'Extended') {
    Write-Host "`n[*] Recogida extendida de procesos, persistencia, seguridad y registros..." -ForegroundColor Cyan

    $Processes = @(Invoke-KronosCollection 'Procesos' {
        Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ PID = $_.ProcessId; PPID = $_.ParentProcessId; Nombre = $_.Name;
                Ruta = $_.ExecutablePath; Comando = $_.CommandLine; Inicio = [string]$_.CreationDate }
        }
    })
    $Services = @(Invoke-KronosCollection 'Servicios' {
        Get-CimInstance Win32_Service -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ Nombre = $_.Name; Estado = $_.State; Inicio = $_.StartMode;
                Cuenta = $_.StartName; Ruta = $_.PathName }
        }
    })
    $ScheduledTasks = @(Invoke-KronosCollection 'Tareas programadas' {
        Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ Nombre = $_.TaskName; Ruta = $_.TaskPath; Estado = $_.State;
                Acciones = (($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; ') }
        }
    })
    $StartupEntries = @(Invoke-KronosCollection 'Inicio automático' {
        $runKeys = @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
        $runKeys += @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction Stop |
            Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } |
            ForEach-Object { "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run" })
        foreach ($runKey in $runKeys) {
            if (-not (Test-Path -LiteralPath $runKey)) { continue }
            $values = Get-ItemProperty -LiteralPath $runKey -ErrorAction Stop
            foreach ($entry in $values.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }) {
                [PSCustomObject]@{ Clave = $runKey; Nombre = $entry.Name; Comando = [string]$entry.Value }
            }
        }
    })
    $LocalUsers = @(Invoke-KronosCollection 'Usuarios locales' {
        Get-LocalUser -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ Nombre = $_.Name; SID = [string]$_.SID; Habilitado = $_.Enabled;
                UltimoInicio = [string]$_.LastLogon; Caduca = [string]$_.AccountExpires }
        }
    })
    $DefenderStatus = @(Invoke-KronosCollection 'Defender' {
        Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled,AntivirusEnabled,
            RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,QuickScanEndTime,FullScanEndTime
    })
    $FirewallProfiles = @(Invoke-KronosCollection 'Firewall' {
        Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction
    })

    $eventLogDir = Join-Path $EvidenceRaw 'EventLogs'
    New-Item -ItemType Directory -Path $eventLogDir -Force | Out-Null
    try {
        $auditPolicyFile = Join-Path $CaseFolder 'AUDIT_POLICY.txt'
        $auditPolicyOutput = & (Join-Path $env:SystemRoot 'System32\auditpol.exe') /get /category:* 2>&1
        if ($LASTEXITCODE -ne 0) { throw "auditpol terminó con código $LASTEXITCODE : $auditPolicyOutput" }
        $auditPolicyOutput | Out-File -LiteralPath $auditPolicyFile -Encoding UTF8
        Register-KronosArtifact 'AUDITPOL:get/category:*' $auditPolicyFile 'auditpol.exe'
    } catch { Add-KronosIssue 'Política de auditoría' $_.Exception.Message }
    $wevtutil = Join-Path $env:SystemRoot 'System32\wevtutil.exe'
    $channels = @('Security','System','Application','Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-TaskScheduler/Operational')
    $sysmonChannel = 'Microsoft-Windows-Sysmon/Operational'
    $sysmonLog = Get-WinEvent -ListLog $sysmonChannel -ErrorAction SilentlyContinue
    $script:CaseMetadata['SysmonAvailable'] = [bool]$sysmonLog
    if ($sysmonLog) {
        $channels += $sysmonChannel
    }
    foreach ($channel in $channels) {
        $safeChannel = $channel -replace '[^A-Za-z0-9_-]', '_'
        $destination = Join-Path $eventLogDir "$safeChannel.evtx"
        try {
            $null = Get-WinEvent -ListLog $channel -ErrorAction Stop
            $nativeOutput = & $wevtutil epl $channel $destination 2>&1
            if ($LASTEXITCODE -ne 0) { throw "wevtutil terminó con código $LASTEXITCODE : $nativeOutput" }
            if (-not (Test-Path -LiteralPath $destination)) { throw 'No se creó el archivo EVTX.' }
            Register-KronosArtifact "EVENTLOG:$channel" $destination 'wevtutil epl'
            $LogExports += [PSCustomObject]@{ Canal = $channel; Estado = 'Exportado'; Archivo = $destination.Substring($CaseFolder.Length + 1) }
        } catch {
            Add-KronosIssue 'EVTX' "$channel : $($_.Exception.Message)"
            $LogExports += [PSCustomObject]@{ Canal = $channel; Estado = 'Fallido'; Archivo = '' }
        }
    }

    Write-Host " [*] Correlacionando accesos, procesos y cambios auditados..." -ForegroundColor Cyan
    $securityIds = @(4624,4625,4634,4647,4648,4657,4663,4688,4698,4702)
    $queriedEvents = @(Get-KronosEvents @{ LogName = 'Security'; Id = $securityIds } -Maximum $SecurityEventLimit)
    $securityRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($eventRecord in $queriedEvents) {
        try { $securityRows.Add((Convert-KronosSecurityEvent $eventRecord)) }
        catch { Add-KronosIssue 'Correlación' "Evento $($eventRecord.RecordId): $($_.Exception.Message)" }
    }
    $SecurityEvents = @($securityRows.ToArray())
    if ($queriedEvents.Count -ge $SecurityEventLimit) {
        Add-KronosIssue 'Correlación' "Se alcanzó el límite de $SecurityEventLimit eventos de Seguridad. El EVTX exportado puede contener eventos anteriores."
    }

    if ($sysmonLog) {
        Write-Host " [*] Correlacionando procesos, red, DNS y archivos registrados por Sysmon..." -ForegroundColor Cyan
        $sysmonIds = @(1,3,11,12,13,14,22,23,26)
        $queriedSysmon = @(Get-KronosEvents @{ LogName = $sysmonChannel; Id = $sysmonIds } -Maximum $SysmonEventLimit)
        $sysmonRows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($eventRecord in $queriedSysmon) {
            try { $sysmonRows.Add((Convert-KronosSysmonEvent $eventRecord)) }
            catch { Add-KronosIssue 'Sysmon' "Evento $($eventRecord.RecordId): $($_.Exception.Message)" }
        }
        $SysmonEvents = @($sysmonRows.ToArray())
        if ($queriedSysmon.Count -ge $SysmonEventLimit) {
            Add-KronosIssue 'Sysmon' "Se alcanzó el límite de $SysmonEventLimit eventos. El EVTX exportado puede contener eventos anteriores."
        }
    }
}

$Timeline = @(
    foreach ($row in $AntiForensicEvents) {
        [PSCustomObject]@{ FechaUTC = $row.FechaUTC; Tipo = 'Vaciado de log'; Detalle = $row.Evento; Fuente = 'EventosBorrado.csv' }
    }
    foreach ($row in $Logons) {
        [PSCustomObject]@{ FechaUTC = $row.FechaUTC; Tipo = $row.Tipo; Detalle = "$($row.Usuario) $($row.IP_Origen)"; Fuente = 'Accesos.csv' }
    }
    foreach ($row in $RecentDocs) {
        [PSCustomObject]@{ FechaUTC = $row.FechaModificacion; Tipo = 'LNK modificado'; Detalle = $row.Archivo; Fuente = 'DocumentosRecientes.csv' }
    }
    foreach ($row in $Prefetch) {
        [PSCustomObject]@{ FechaUTC = $row.FechaModificacion; Tipo = 'Prefetch modificado'; Detalle = $row.Binario; Fuente = 'Prefetch.csv' }
    }
    foreach ($row in $SecurityEvents) {
        $detail = "$($row.Usuario) SID=$($row.SID) Sesión=$($row.LogonID) Origen=$($row.IPOrigen) $($row.Proceso) $($row.Objeto)"
        [PSCustomObject]@{ FechaUTC = $row.FechaUTC; Tipo = $row.Accion; Detalle = $detail.Trim(); Fuente = 'EventosAuditoria.csv' }
    }
    foreach ($row in $SysmonEvents) {
        $detail = "$($row.Usuario) GUID=$($row.ProcessGuid) $($row.Proceso) $($row.IPDestino) $($row.ConsultaDNS) $($row.Archivo) $($row.ObjetoRegistro)"
        [PSCustomObject]@{ FechaUTC = $row.FechaUTC; Tipo = "Sysmon: $($row.Accion)"; Detalle = $detail.Trim(); Fuente = 'SysmonEvents.csv' }
    }
    foreach ($row in $BrowserVisits) {
        if ($row.FechaUTC) {
            [PSCustomObject]@{ FechaUTC = $row.FechaUTC; Tipo = 'Visita de navegador'; Detalle = "$($row.Usuario)/$($row.Perfil) $($row.URL)"; Fuente = 'BrowserVisits.csv' }
        }
    }
    foreach ($row in $BrowserDownloads) {
        if ($row.InicioUTC) {
            [PSCustomObject]@{ FechaUTC = $row.InicioUTC; Tipo = 'Descarga registrada'; Detalle = "$($row.Usuario)/$($row.Perfil) $($row.URL) -> $($row.RutaDestino)"; Fuente = 'BrowserDownloads.csv' }
        }
    }
) | Sort-Object FechaUTC -Descending

if ($TranscriptStarted) {
    try { Stop-Transcript -ErrorAction Stop | Out-Null }
    catch { throw "No se pudo cerrar la transcripción antes de calcular los hashes: $($_.Exception.Message)" }
}

# ------------------------------------------------------------------------------
# 6. GENERACIÓN DEL DASHBOARD FORENSE (HTML DARK CYBERPUNK)
# ------------------------------------------------------------------------------
Write-Host "`n[*] Preparando el informe de triage..." -ForegroundColor Cyan
Add-Type -AssemblyName System.Web

function Build-Table($items, $title,$accentColor) {
    if (-not $items -or $items.Count -eq 0) {
        return "<div class='panel'><h3>$([System.Web.HttpUtility]::HtmlEncode($title))</h3><p class='muted'>Sin registros observados o disponibles; consulte las incidencias.</p></div>"
    }
    $headers = @($items[0].PSObject.Properties | Select-Object -ExpandProperty Name)
    $th = ($headers | ForEach-Object { "<th>$([System.Web.HttpUtility]::HtmlEncode($_))</th>" }) -join ""
    $tr = ""
    foreach ($row in $items) {$td = ""
        foreach ($h in $headers) {$val = [string]$row.$h
            $safeVal = [System.Web.HttpUtility]::HtmlEncode($val)
            if ($val -match "CRÍTICO|VACIADO") {
                $td += "<td class='tag-crit'>$safeVal</td>"
            } elseif ($val -match "SOSPECHOSO") {
                $td += "<td class='tag-susp'>$safeVal</td>"
            } else {
                $td += "<td>$safeVal</td>"
            }
        }
        $tr += "<tr>$td</tr>"
    }
    return @"
    <div class='panel'>
        <h3 style='border-left: 4px solid $accentColor;'>$([System.Web.HttpUtility]::HtmlEncode($title)) <span class='badge'>$($items.Count)</span></h3>
        <div class='scrollbox'>
            <table>
                <thead><tr>$th</tr></thead>
                <tbody>$tr</tbody>
            </table>
        </div>
    </div>
"@
}

$OS = Get-CimInstance Win32_OperatingSystem
$ReportFile = Join-Path $CaseFolder "KRONOS_INFORME_FORENSE.html"
$safeHost = [System.Web.HttpUtility]::HtmlEncode($env:COMPUTERNAME)
$safeOS = [System.Web.HttpUtility]::HtmlEncode($OS.Caption)
$safeBoot = [System.Web.HttpUtility]::HtmlEncode([string]$OS.LastBootUpTime)
$safeCaseId = [System.Web.HttpUtility]::HtmlEncode($CaseId)
$safeOperator = [System.Web.HttpUtility]::HtmlEncode($Operator)
$safeBrowserStatus = [System.Web.HttpUtility]::HtmlEncode([string]$script:CaseMetadata['BrowserAnalysis'])

if ($script:ArtifactSources.Count -gt 0) {
    $script:ArtifactSources | Export-Csv -LiteralPath (Join-Path $CaseFolder 'ARTIFACT_SOURCES.csv') -NoTypeInformation -Encoding UTF8
}

$DataSets = [ordered]@{
    EventosBorrado = $AntiForensicEvents
    Navegadores = $BrowserArtifacts
    Accesos = $Logons
    Conexiones = $NetworkSockets
    Busquedas = $Searches
    DocumentosRecientes = $RecentDocs
    Prefetch = $Prefetch
    USB = $USBDevices
    Cronologia = $Timeline
    Incidencias = $script:CollectionIssues
}
if ($CollectionProfile -eq 'Extended') {
    $DataSets['Procesos'] = $Processes
    $DataSets['Servicios'] = $Services
    $DataSets['TareasProgramadas'] = $ScheduledTasks
    $DataSets['InicioAutomatico'] = $StartupEntries
    $DataSets['UsuariosLocales'] = $LocalUsers
    $DataSets['Defender'] = $DefenderStatus
    $DataSets['Firewall'] = $FirewallProfiles
    $DataSets['RegistrosEVTX'] = $LogExports
    $DataSets['EventosAuditoria'] = $SecurityEvents
    $DataSets['SysmonEvents'] = $SysmonEvents
}
foreach ($dataName in $DataSets.Keys) {
    if ($DataSets[$dataName]) {
        Export-KronosCsv @($DataSets[$dataName]) (Join-Path $CaseFolder "$dataName.csv")
    }
}

$ExtendedHtml = ''
if ($CollectionProfile -eq 'Extended') {
    $ExtendedHtml += Build-Table $Processes 'Procesos en ejecución' '#38bdf8'
    $ExtendedHtml += Build-Table $Services 'Servicios' '#38bdf8'
    $ExtendedHtml += Build-Table $ScheduledTasks 'Tareas programadas' '#38bdf8'
    $ExtendedHtml += Build-Table $StartupEntries 'Inicio automático' '#38bdf8'
    $ExtendedHtml += Build-Table $LocalUsers 'Usuarios locales' '#38bdf8'
    $ExtendedHtml += Build-Table $DefenderStatus 'Estado de Microsoft Defender' '#38bdf8'
    $ExtendedHtml += Build-Table $FirewallProfiles 'Perfiles de firewall' '#38bdf8'
    $ExtendedHtml += Build-Table $LogExports 'Exportación de registros EVTX' '#38bdf8'
    $ExtendedHtml += Build-Table @($SecurityEvents | Select-Object -First 200) 'Eventos auditados recientes (200 visibles; CSV completo)' '#38bdf8'
    $ExtendedHtml += Build-Table @($SysmonEvents | Select-Object -First 200) 'Sysmon (200 visibles; CSV completo)' '#38bdf8'
}

$DashboardHtml = @"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>KRONOS | kronos Version 1.0 by JLC - $safeHost</title>
    <style>
        body { font-family: 'Segoe UI', Consolas, sans-serif; background: #080c14; color: #cbd5e1; margin: 0; padding: 25px; }
        h1 { color: #00f0ff; font-size: 24px; margin-bottom: 2px; }
        .sub { font-size: 12px; color: #64748b; margin-bottom: 20px; text-transform: uppercase; }
        .meta-strip { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
        .meta-card { background: #0f172a; border: 1px solid #1e293b; border-radius: 6px; padding: 10px 14px; font-size: 13px; }
        .meta-card b { color: #00f0ff; }
        .panel { background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 14px; margin-bottom: 20px; }
        h3 { font-size: 14px; color: #f8fafc; margin-top: 0; padding-left: 8px; display: flex; align-items: center; justify-content: space-between; }
        .badge { background: #334155; font-size: 11px; padding: 2px 7px; border-radius: 10px; color: #fff; }
        .scrollbox { max-height: 350px; overflow-y: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 12px; }
        th { background: #1e293b; color: #94a3b8; text-align: left; padding: 8px; position: sticky; top: 0; }
        td { padding: 8px; border-bottom: 1px solid #1e293b; color: #e2e8f0; word-break: break-all; }
        tr:hover { background: #162032; }
        .tag-crit { color: #ff3366 !important; font-weight: bold; background: rgba(255, 51, 102, 0.1); }
        .tag-susp { color: #ffaa00 !important; font-weight: bold; background: rgba(255, 170, 0, 0.1); }
        .muted { color: #64748b; font-size: 12px; }
        .footer { margin-top: 30px; font-size: 11px; color: #475569; text-align: center; border-top: 1px solid #1e293b; padding-top: 15px; }
    </style>
</head>
<body>
<h1>KRONOS</h1>
<div class='sub'>Kit de Recolección, Organización y Normalización de Observaciones de Seguridad</div>
<div class='sub'>kronos Version 1.0 by JLC • Triage forense en vivo</div>

    <div class='meta-strip'>
        <div class='meta-card'>Hostname: <b>$safeHost</b></div>
        <div class='meta-card'>Caso: <b>$safeCaseId</b></div>
        <div class='meta-card'>Operador declarado: <b>$safeOperator</b></div>
        <div class='meta-card'>Perfil: <b>$CollectionProfile</b></div>
        <div class='meta-card'>Análisis de navegador: <b>$safeBrowserStatus</b></div>
        <div class='meta-card'>Sistema Operativo: <b>$safeOS</b></div>
        <div class='meta-card'>Arranque: <b>$safeBoot</b></div>
        <div class='meta-card'>VBS: <b>$VbsRunning</b></div>
        <div class='meta-card'>HVCI: <b>$HvciRunning</b></div>
    </div>

    $(Build-Table $script:CollectionIssues "Incidencias de adquisición" "#ff3366")
    $(Build-Table $AntiForensicEvents "1. Eventos de vaciado (1102 / 104)" "#ff3366")
    $(Build-Table $BrowserArtifacts "2. Historiales de navegación copiados (Chromium SQLite)" "#00f0ff")
    $(Build-Table @($BrowserVisits | Select-Object -First 200) "Visitas registradas (200 visibles; CSV completo)" "#00f0ff")
    $(Build-Table @($BrowserDownloads | Select-Object -First 200) "Descargas registradas (200 visibles; CSV completo)" "#00f0ff")
    $(Build-Table $Logons "3. Accesos RDP y de red (evento 4624)" "#3b82f6")
    $(Build-Table $NetworkSockets "4. Conexiones TCP y hashes de ejecutables" "#10b981")
    $(Build-Table $Searches "5. Búsquedas de Explorer en hives cargados" "#f59e0b")
    $(Build-Table $RecentDocs "6. Accesos directos recientes (.LNK)" "#8b5cf6")
    $(Build-Table $Prefetch "7. Archivos Prefetch (.pf)" "#ec4899")
    $(Build-Table $USBDevices "8. Dispositivos USB registrados" "#14b8a6")
    $(Build-Table @($Timeline | Select-Object -First 300) "Cronología (UTC; 300 visibles; CSV completo)" "#eab308")
    $(Build-Table $script:ArtifactSources "Procedencia de las capturas" "#a855f7")
    $ExtendedHtml

    <div class='footer'>Copyright (c) 2026 JLC. Todos los derechos reservados.<br>Triage en vivo: los hashes documentan las copias; el análisis debe considerar las incidencias y las limitaciones de una captura en caliente.</div>
</body>
</html>
"@

$DashboardHtml | Out-File -FilePath $ReportFile -Encoding UTF8

# ------------------------------------------------------------------------------
# 7. MANIFIESTO SHA-256 DE LOS ARCHIVOS DEL CASO
# ------------------------------------------------------------------------------
Write-Host " [*] Calculando hashes SHA-256 de los archivos del caso..." -ForegroundColor Gray

$script:CaseMetadata['FinishedUTC'] = (Get-Date).ToUniversalTime().ToString('o')
$script:CaseMetadata['Status'] = if ($script:CollectionIssues.Count -gt 0) { 'COMPLETE_WITH_ISSUES' } else { 'COMPLETE' }
$script:CaseMetadata['Issues'] = $script:CollectionIssues.Count
$script:CaseMetadata | ConvertTo-Json -Depth 4 | Out-File -LiteralPath $MetadataFile -Encoding UTF8

$provenanceMap = @{}
foreach ($record in $script:ArtifactSources) { $provenanceMap[$record.RelativePath] = $record }
$ManifestFile = Join-Path $CaseFolder "MANIFEST_HASHES_SHA256.csv"
$Manifest = Get-ChildItem -LiteralPath $CaseFolder -Recurse -File | Where-Object { $_.FullName -ne $ManifestFile } | ForEach-Object {
    $relative = $_.FullName.Substring($CaseFolder.Length + 1)
    $provenance = $provenanceMap[$relative]
    [PSCustomObject]@{
        FechaHashUTC    = (Get-Date).ToUniversalTime().ToString('o')
        Archivo         = $_.Name
        Hash_SHA256     = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash
        TamanoBytes     = $_.Length
        RutaRelativa    = $relative
        Fuente          = if ($provenance) { $provenance.Source } else { 'Generado por kronos' }
        Metodo          = if ($provenance) { $provenance.Method } else { 'Generación de informe' }
        CapturaUTC      = if ($provenance) { $provenance.CapturedUTC } else { $null }
    }
}

$Manifest | Export-Csv -LiteralPath $ManifestFile -NoTypeInformation -Encoding UTF8

Write-Host "`n================================================================================" -ForegroundColor Green
Write-Host " [✓] TRIAGE FINALIZADO: revise el informe y las incidencias antes de interpretar los resultados" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green
Write-Host " [>] Carpeta del Caso  : $CaseFolder" -ForegroundColor Yellow
Write-Host " [>] Panel Interactivo : $ReportFile" -ForegroundColor White
Write-Host " [>] Manifiesto SHA256 : $ManifestFile`n" -ForegroundColor Cyan
