<#
.SYNOPSIS
    LocNet installer for Windows.

.DESCRIPTION
    Installs locnetd as a Windows service plus the locnet CLI, and adds the
    install directory to the system PATH.

    Must be run from an elevated PowerShell prompt: the service creates a
    network interface.

.PARAMETER Hub
    Also install locnet-hub. Only needed on the always-on machine.

.PARAMETER SkipWintun
    Do not fetch wintun.dll. The tunnel cannot be created without it, so this
    leaves a machine that installs but cannot join; it is here for air-gapped
    installs where the DLL is placed by hand, and for anyone who would rather
    the installer touch nothing on the network.

    By default the DLL is downloaded from wintun.net and checked against a
    pinned SHA256 before use. It is not bundled in this archive: it ships under
    its own licence and its own signature, and redistributing someone else's
    signed kernel driver inside an unrelated project is a bad habit and a
    licensing question nobody needs. Downloading a pinned, checksummed file
    raises neither.

.PARAMETER Join
    A join code. The installer joins the network as its last step, so one
    command leaves the machine on the mesh rather than merely holding the
    software.

.PARAMETER Uninstall
    Stop and remove the service and the binaries. State is left in place.

.EXAMPLE
    .\install.ps1
    .\install.ps1 -Join locnet1_jrhacahjfq5r5wgdb63ls2gxd6nx3exn
    .\install.ps1 -Hub
    .\install.ps1 -SkipWintun
    .\install.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [switch]$Hub,
    [switch]$SkipWintun,
    [switch]$Uninstall,
    [string]$Join = '',
    [string]$InstallDir = "$env:ProgramFiles\LocNet"
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "install.ps1 must be run from an elevated PowerShell prompt (Run as Administrator)."
    }
}

# The binaries are built with a Go toolchain that requires Windows 10 or later.
# On anything older the runtime resolves a kernel32 export that is not there and
# calls a null pointer, which surfaces as an 0xc0000005 crash dump with PC=0x0 -
# or, once installed as a service, as a bare "cannot start service" with nothing
# in the log. Neither points at the real cause, so refuse before installing.
#
# WMI rather than [Environment]::OSVersion, which reports 6.2 on anything newer
# than Windows 8 unless the calling process carries a compatibility manifest.
function Assert-SupportedWindows {
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $version = [Version]$os.Version
    if ($version.Major -lt 10) {
        throw @"
LocNet requires Windows 10 or later. This machine reports $($os.Caption) (version $($os.Version)).

The binaries cannot start on this version - they fail during runtime
initialisation, before any LocNet code runs, so there is no configuration or
driver that would make them work.

Nothing has been installed.
"@
    }
}

function Remove-LocNet {
    Write-Host "Stopping and removing LocNet..."
    if (Get-Service -Name locnetd -ErrorAction SilentlyContinue) {
        Stop-Service -Name locnetd -Force -ErrorAction SilentlyContinue
        # sc.exe rather than Remove-Service, which only exists on PowerShell 6+.
        & sc.exe delete locnetd | Out-Null
    }
    if (Test-Path $InstallDir) {
        Remove-Item -Recurse -Force $InstallDir
    }
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $kept = ($path -split ';' | Where-Object { $_ -and $_ -ne $InstallDir }) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $kept, 'Machine')

    Write-Host ""
    Write-Host "Removed. State was left at $env:ProgramData\LocNet."
    Write-Host "Delete that folder if you want this machine to forget its identity."
}

# Uninstall skips the version check: a machine that got a half-install from an
# older copy of this script still needs to be able to clean it up.
if ($Uninstall) { Assert-Admin; Remove-LocNet; return }

# Version before privileges. The OS check needs no rights, and telling someone
# to go and re-launch elevated only to then tell them their Windows is too old
# is two trips for one answer.
Assert-SupportedWindows
Assert-Admin

$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# ------------------------------------------------------------------ binaries

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# An upgrade has to stop the old service first. Windows will not overwrite an
# executable that is running, so copying over a live locnetd.exe fails with
# "being used by another process" and the install stops half done.
if (Get-Service -Name locnetd -ErrorAction SilentlyContinue) {
    Write-Host "Stopping the running service for the upgrade..."
    Stop-Service -Name locnetd -Force -ErrorAction SilentlyContinue
    (Get-Service -Name locnetd).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

$binaries = @('locnetd.exe', 'locnet.exe')
if ($Hub) { $binaries += 'locnet-hub.exe' }

Write-Host "Installing binaries:"
foreach ($bin in $binaries) {
    $src = Join-Path $here $bin
    if (-not (Test-Path $src)) {
        throw "Cannot find $bin next to this script. Run it from an unpacked release directory."
    }
    Copy-Item $src (Join-Path $InstallDir $bin) -Force
    Write-Host "  $InstallDir\$bin"
}

# ------------------------------------------------------------------- wintun

# wintun.dll is the kernel-mode tunnel driver, and the tunnel cannot be created
# without it. It is not bundled in this archive: it ships under its own licence
# and its own signature, and redistributing someone else's signed kernel driver
# inside an unrelated project invites a licensing question and makes us the
# distributor of a driver we do not maintain. Fetching a pinned, checksummed
# copy from the vendor avoids both while still leaving nothing for the operator
# to do by hand.
#
# The version and its hash are pinned together. Verifying before use is the
# whole point: this file is loaded into the kernel, so an unverified download
# is the most dangerous single step in this script. A hash mismatch is fatal
# rather than a warning.
$wintunVersion = '0.14.1'
$wintunSHA256 = '07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51'
$wintunPath = Join-Path $InstallDir 'wintun.dll'
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }

if (Test-Path (Join-Path $here 'wintun.dll')) {
    Copy-Item (Join-Path $here 'wintun.dll') $wintunPath -Force
    Write-Host "  $wintunPath (from the release directory)"
} elseif (-not $SkipWintun) {
    $url = "https://www.wintun.net/builds/wintun-$wintunVersion.zip"
    Write-Host "Downloading wintun $wintunVersion from wintun.net..."
    $tmp = Join-Path $env:TEMP "wintun-$([guid]::NewGuid()).zip"
    $extract = Join-Path $env:TEMP "wintun-$([guid]::NewGuid())"
    try {
        # Invoke-WebRequest without a progress bar is an order of magnitude
        # faster on a large file: rendering the bar dominates the transfer.
        $prevProgress = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
        $ProgressPreference = $prevProgress

        $got = (Get-FileHash -Path $tmp -Algorithm SHA256).Hash
        if ($got -ne $wintunSHA256) {
            throw @"
wintun download does not match its published checksum.

  expected  $wintunSHA256
  got       $got
  from      $url

Nothing was installed. This means the file was corrupted in transit or is not
the file it should be; either way it must not be loaded into the kernel. Verify
the checksum published at https://www.wintun.net and retry, or install
wintun.dll by hand and re-run with -SkipWintun.
"@
        }

        Expand-Archive -Path $tmp -DestinationPath $extract -Force
        $dll = Join-Path $extract "wintun\bin\$arch\wintun.dll"
        if (-not (Test-Path $dll)) {
            throw "The wintun archive has no $arch build at wintun\bin\$arch\wintun.dll."
        }
        Copy-Item $dll $wintunPath -Force
        Write-Host "  $wintunPath (verified SHA256)"
    } finally {
        Remove-Item $tmp, $extract -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------- PATH + svc

$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($path -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable('Path', "$path;$InstallDir", 'Machine')
    Write-Host "`nAdded $InstallDir to the system PATH (new shells only)."
}

Write-Host "`nInstalling the service:"
if (Get-Service -Name locnetd -ErrorAction SilentlyContinue) {
    Stop-Service -Name locnetd -Force -ErrorAction SilentlyContinue
    & sc.exe delete locnetd | Out-Null
    Start-Sleep -Seconds 1
}

New-Service -Name locnetd `
    -BinaryPathName "`"$InstallDir\locnetd.exe`"" `
    -DisplayName 'LocNet node agent' `
    -Description 'Joins this machine to a LocNet private mesh network.' `
    -StartupType Automatic | Out-Null

# Restart on failure instead of giving up, matching the systemd and launchd
# units. The usual cause of an exit is a hub that is briefly unreachable.
& sc.exe failure locnetd reset= 86400 actions= restart/5000/restart/5000/restart/15000 | Out-Null

Write-Host "  service 'locnetd' created"

if (Test-Path $wintunPath) {
    Start-Service -Name locnetd
    Write-Host "  service started"
} else {
    Write-Host "  service NOT started - wintun.dll is missing" -ForegroundColor Yellow
}

# -------------------------------------------------------------- next steps

Write-Host ""
if (-not (Test-Path $wintunPath)) {
    Write-Host "wintun.dll is required and was not installed." -ForegroundColor Yellow
    Write-Host "  Download it from https://www.wintun.net, take bin\$arch\wintun.dll"
    Write-Host "  from the archive, and copy it to:"
    Write-Host "      $InstallDir\wintun.dll"
    Write-Host "  Then run:  Start-Service locnetd"
    Write-Host "  Or re-run this installer without -SkipWintun to fetch it automatically."
    Write-Host ""
}

$locnetExe = Join-Path $InstallDir 'locnet.exe'

# Joining without the tunnel driver would fail in a way that reads as a bad
# join code, sending people to the hub to mint another one. The real problem is
# one missing file, and it is worth saying so before the confusing error rather
# than after it.
if ($Join -and -not (Test-Path $wintunPath)) {
    Write-Host ""
    Write-Host "Not joining yet: wintun.dll is missing, so the tunnel cannot be created." -ForegroundColor Yellow
    Write-Host "Install it as described above, then run:"
    Write-Host "     locnet join $Join"
    exit 1
}

if ($Join) {
    Write-Host "Joining the network..."
    # The service has only just started and may not have its control socket up
    # yet. Waiting turns a race into a reliable install.
    for ($i = 0; $i -lt 20; $i++) {
        # 2>&1 | Out-Null rather than *> $null, which needs PowerShell 3+.
        & $locnetExe status 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { break }
        Start-Sleep -Milliseconds 500
    }

    & $locnetExe join $Join
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        & $locnetExe status
        Write-Host ""
        Write-Host "This machine is on the network. Check the others with:  locnet peers"
        exit 0
    }

    # A failed join is not a failed install: the software is in place and the
    # code can be retried without repeating any of this.
    Write-Host ""
    Write-Host "The software is installed, but joining failed - see the error above." -ForegroundColor Yellow
    Write-Host "The usual causes are a code that has been used up or has expired, and a"
    Write-Host "hub that is not reachable from this network. Get a fresh code and retry:"
    Write-Host "     locnet join <code>"
    exit 1
}

Write-Host "Next:"
Write-Host "  1. Get a join code from whoever runs the hub:  locnet-hub invite"
Write-Host "  2. On this machine:                            locnet join <code>"
Write-Host "  3. Check it worked:                            locnet status"
Write-Host ""
# The desktop helper runs in the interactive session, not in the service: a
# Windows service lives in session 0, whose desktop is a blank virtual one
# nobody is looking at. So it is started by the person logged in, not here.
Write-Host "Optional - let others watch this screen from their browser (no client needed):"
Write-Host "     locnet desktop share -allow <who> -control   # elevated, once"
Write-Host "     locnet desktop autostart                     # as the logged-in user"
Write-Host "  The second one must run in the desktop session you want shared."
Write-Host ""
Write-Host "Optional - let this machine run queued work for the fleet:"
Write-Host "     locnet compute enable -allow <who> -allow-privileged"
Write-Host "     locnet queue submit -- <command>             # from anywhere allowed"
Write-Host ""
