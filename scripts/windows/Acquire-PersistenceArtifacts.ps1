#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Server,

    [Parameter(Mandatory = $true)]
    [string]$RemoteUser,

    [string]$RemotePath = "/home/wazuh/uploads",

    [int]$Port = 22,

    [string]$SshKeyPath,

    [string]$LocalRoot = "$env:ProgramData\PersistenceCollector\staging",

    [string]$HostnameOverride,

    [switch]$SkipScheduledTasks,

    [switch]$SkipServices,

    [switch]$IncludeSysmon,

    [switch]$IncludeWmi,

    [switch]$KeepLocalCopy
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ModuleVersion = "0.1.0"
$Shadow = $null
$StageDir = $null
$CollectedFiles = New-Object System.Collections.Generic.List[object]

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-SafeName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return "unknown"
    }

    return ($Name -replace "[^A-Za-z0-9._-]", "_")
}

function Join-ShadowPath {
    param(
        [string]$ShadowRoot,
        [string]$RelativePath
    )

    return ($ShadowRoot.TrimEnd("\") + "\" + $RelativePath.TrimStart("\"))
}

function Get-RelativePath {
    param(
        [string]$BasePath,
        [string]$Path
    )

    $base = (Resolve-Path -LiteralPath $BasePath).Path.TrimEnd("\") + "\"
    $full = (Resolve-Path -LiteralPath $Path).Path

    if ($full.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {
        return $full.Substring($base.Length)
    }

    return $full
}

function Add-ManifestEntry {
    param(
        [string]$Path,
        [string]$ArtifactType
    )

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) {
        Write-Verbose "Skipping manifest entry for missing file: $Path"
        return
    }

    try {
        $hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop
    }
    catch {
        Write-Warning "Skipping manifest entry for unreadable file ${Path}: $($_.Exception.Message)"
        return
    }

    $CollectedFiles.Add([pscustomobject]@{
        artifact_type = $ArtifactType
        relative_path = Get-RelativePath -BasePath $StageDir -Path $Path
        size_bytes = $item.Length
        sha256 = $hash.Hash
    }) | Out-Null
}

function Copy-FileIfExists {
    param(
        [string]$Source,
        [string]$Destination,
        [string]$ArtifactType
    )

    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        Write-Verbose "Missing source file: $Source"
        return $false
    }

    $parent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination -Force -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $Destination -PathType Leaf)) {
        Write-Warning "Copy operation did not create expected file: $Destination"
        return $false
    }

    Add-ManifestEntry -Path $Destination -ArtifactType $ArtifactType
    return $true
}

function Copy-DirectoryContentsIfExists {
    param(
        [string]$SourceDirectory,
        [string]$DestinationDirectory,
        [string]$ArtifactType
    )

    if (-not (Test-Path -LiteralPath $SourceDirectory -PathType Container)) {
        Write-Verbose "Missing source directory: $SourceDirectory"
        return 0
    }

    New-Item -ItemType Directory -Path $DestinationDirectory -Force | Out-Null
    $count = 0

    Get-ChildItem -LiteralPath $SourceDirectory -Recurse -File -Force | ForEach-Object {
        $relative = $_.FullName.Substring($SourceDirectory.Length).TrimStart("\")
        $destination = Join-Path $DestinationDirectory $relative
        $parent = Split-Path -Parent $destination
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
        Copy-Item -LiteralPath $_.FullName -Destination $destination -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $destination -PathType Leaf) {
            Add-ManifestEntry -Path $destination -ArtifactType $ArtifactType
            $count++
        }
        else {
            Write-Warning "Copy operation did not create expected file: $destination"
        }
    }

    return $count
}

function Export-ServicesMetadata {
    param([string]$Destination)

    $services = Get-CimInstance -ClassName Win32_Service |
        Select-Object Name, DisplayName, State, StartMode, PathName, ServiceType, StartName, Description

    New-Item -ItemType Directory -Path (Split-Path -Parent $Destination) -Force | Out-Null
    $services | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Destination -Encoding UTF8
    Add-ManifestEntry -Path $Destination -ArtifactType "services"
}

function Export-WmiPersistenceMetadata {
    param([string]$DestinationDirectory)

    New-Item -ItemType Directory -Path $DestinationDirectory -Force | Out-Null
    $classes = @("__EventFilter", "CommandLineEventConsumer", "ActiveScriptEventConsumer", "__FilterToConsumerBinding")

    foreach ($className in $classes) {
        $destination = Join-Path $DestinationDirectory "$className.json"

        try {
            $items = Get-CimInstance -Namespace "root/subscription" -ClassName $className |
                Select-Object * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties
            $items | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $destination -Encoding UTF8
            Add-ManifestEntry -Path $destination -ArtifactType "wmi"
        }
        catch {
            Write-Warning "Failed to export WMI class ${className}: $($_.Exception.Message)"
        }
    }
}

if (-not (Test-IsAdministrator)) {
    throw "Run this script from an elevated PowerShell session. VSS snapshot creation requires administrator privileges."
}

if (-not (Get-Command scp -ErrorAction SilentlyContinue)) {
    throw "OpenSSH scp was not found. Install the Windows OpenSSH Client feature before running acquisition."
}

if ($SshKeyPath -and -not (Test-Path -LiteralPath $SshKeyPath -PathType Leaf)) {
    throw "SSH key path does not exist: $SshKeyPath"
}

$HostName = if ($HostnameOverride) { $HostnameOverride } else { $env:COMPUTERNAME }
$SafeHostName = ConvertTo-SafeName -Name $HostName
$Timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$StageDir = Join-Path $LocalRoot "$SafeHostName`_$Timestamp"

try {
    New-Item -ItemType Directory -Path $StageDir -Force | Out-Null

    $volume = "$($env:SystemDrive)\"
    $createResult = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{
        Volume = $volume
        Context = "ClientAccessible"
    }

    if ($createResult.ReturnValue -ne 0) {
        throw "VSS snapshot creation failed for $volume with return value $($createResult.ReturnValue)."
    }

    $Shadow = Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object { $_.ID -eq $createResult.ShadowID }
    if (-not $Shadow) {
        throw "VSS snapshot was created but could not be found by ID $($createResult.ShadowID)."
    }

    $shadowRoot = $Shadow.DeviceObject
    Write-Host "Created VSS snapshot $($Shadow.ID) at $shadowRoot"

    $regDir = Join-Path $StageDir "Reg"
    $systemHives = @("SOFTWARE", "SYSTEM", "SAM", "SECURITY")

    foreach ($hiveName in $systemHives) {
        foreach ($suffix in @("", ".LOG1", ".LOG2")) {
            $source = Join-ShadowPath -ShadowRoot $shadowRoot -RelativePath "Windows\System32\Config\$hiveName$suffix"
            $destination = Join-Path $regDir "$hiveName$suffix"
            Copy-FileIfExists -Source $source -Destination $destination -ArtifactType "system_hive" | Out-Null
        }
    }

    $usersRoot = Join-ShadowPath -ShadowRoot $shadowRoot -RelativePath "Users"
    if (Test-Path -LiteralPath $usersRoot -PathType Container) {
        $excludedProfiles = @("Public", "Default", "Default User", "All Users")

        Get-ChildItem -LiteralPath $usersRoot -Directory -Force | Where-Object {
            $_.Name -notin $excludedProfiles
        } | ForEach-Object {
            $safeUser = ConvertTo-SafeName -Name $_.Name
            $profileRoot = $_.FullName

            $ntuserFiles = @(
                @{ Source = "NTUSER.DAT"; Destination = "$safeUser.DAT" },
                @{ Source = "NTUSER.DAT.LOG1"; Destination = "$safeUser.LOG1" },
                @{ Source = "NTUSER.DAT.LOG2"; Destination = "$safeUser.LOG2" }
            )

            foreach ($file in $ntuserFiles) {
                $source = Join-Path $profileRoot $file.Source
                $destination = Join-Path (Join-Path $StageDir "NTUSER") $file.Destination
                Copy-FileIfExists -Source $source -Destination $destination -ArtifactType "ntuser_hive" | Out-Null
            }

            $usrClassRoot = Join-Path $profileRoot "AppData\Local\Microsoft\Windows"
            $usrClassFiles = @(
                @{ Source = "UsrClass.dat"; Destination = "$safeUser.DAT" },
                @{ Source = "UsrClass.dat.LOG1"; Destination = "$safeUser.LOG1" },
                @{ Source = "UsrClass.dat.LOG2"; Destination = "$safeUser.LOG2" }
            )

            foreach ($file in $usrClassFiles) {
                $source = Join-Path $usrClassRoot $file.Source
                $destination = Join-Path (Join-Path $StageDir "UsrClass") $file.Destination
                Copy-FileIfExists -Source $source -Destination $destination -ArtifactType "usrclass_hive" | Out-Null
            }
        }
    }

    if (-not $SkipScheduledTasks) {
        $tasksSource = Join-ShadowPath -ShadowRoot $shadowRoot -RelativePath "Windows\System32\Tasks"
        $tasksDestination = Join-Path $StageDir "ScheduledTasks"
        Copy-DirectoryContentsIfExists -SourceDirectory $tasksSource -DestinationDirectory $tasksDestination -ArtifactType "scheduled_task" | Out-Null
    }

    if (-not $SkipServices) {
        Export-ServicesMetadata -Destination (Join-Path $StageDir "Services\services.json")
    }

    if ($IncludeSysmon) {
        $sysmonSource = Join-ShadowPath -ShadowRoot $shadowRoot -RelativePath "Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"
        $sysmonDestination = Join-Path $StageDir "EventLogs\Microsoft-Windows-Sysmon%4Operational.evtx"
        Copy-FileIfExists -Source $sysmonSource -Destination $sysmonDestination -ArtifactType "sysmon_evtx" | Out-Null
    }

    if ($IncludeWmi) {
        Export-WmiPersistenceMetadata -DestinationDirectory (Join-Path $StageDir "WMI")
    }

    $manifest = [ordered]@{
        module = "windows-persistence-detection"
        module_version = $ModuleVersion
        host_name = $HostName
        acquired_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        vss_shadow_id = $Shadow.ID
        source_volume = $volume
        files = $CollectedFiles
    }

    $manifestPath = Join-Path $StageDir "manifest.json"
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    $scpArgs = @("-r", "-P", "$Port")
    if ($SshKeyPath) {
        $scpArgs += @("-i", $SshKeyPath)
    }

    $scpArgs += @($StageDir, "${RemoteUser}@${Server}:$RemotePath/")
    Write-Host "Transferring $StageDir to ${RemoteUser}@${Server}:$RemotePath/"
    & scp @scpArgs

    if ($LASTEXITCODE -ne 0) {
        throw "scp failed with exit code $LASTEXITCODE."
    }

    Write-Host "Acquisition completed. Uploaded directory: $SafeHostName`_$Timestamp"
}
finally {
    if ($Shadow) {
        try {
            Remove-CimInstance -InputObject $Shadow -ErrorAction Stop
            Write-Host "Removed VSS snapshot $($Shadow.ID)"
        }
        catch {
            Write-Warning "Failed to remove VSS snapshot $($Shadow.ID): $($_.Exception.Message)"
        }
    }

    if ($StageDir -and (Test-Path -LiteralPath $StageDir) -and (-not $KeepLocalCopy)) {
        Remove-Item -LiteralPath $StageDir -Recurse -Force
        Write-Host "Removed local staging directory $StageDir"
    }
}
