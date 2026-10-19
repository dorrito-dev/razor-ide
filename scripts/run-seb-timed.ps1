<#
  run-seb-timed.ps1 -- run Razor inside Safe Exam Browser for a fixed time, then
  forcibly return the machine to normal (kill SEB, kill Razor, stop the SEB
  service if we were the ones who needed it).

  Why this exists: SEB in this build has allowQuit=true in dev, but the kiosk
  still has no timer and Razor's own killer (killSebProcesses) only targets
  SafeExamBrowser.exe -- it leaves SafeExamBrowser.Client.exe and the CefSharp
  browser subprocesses alive, which keeps the desktop locked. So the quit has to
  be done from outside, over every SEB image, with the service handled too.

  Safety ordering on quit:
    1. graceful WM_CLOSE to razor node   (== SIGINT: gate/terminal/server/audit)
    2. taskkill every SafeExamBrowser image (/T /F), main exe last
    3. stop the SafeExamBrowser service only if it was NOT running before we
       started (it normally is: StartType=Automatic), so we never change the
       machine's baseline
    4. verify: no SEB process, no SEB runtime, no razor node, port released

  Usage:
    powershell -ExecutionPolicy Bypass -File scripts/run-seb-timed.ps1
    powershell -ExecutionPolicy Bypass -File scripts/run-seb-timed.ps1 -Minutes 2 -OpenBrowser
    powershell -ExecutionPolicy Bypass -File scripts/run-seb-timed.ps1 -Fullscreen
#>
[CmdletBinding()]
param(
  [double] $Minutes = 1,
  [int]    $Port = 0,
  [switch] $OpenBrowser,
  [switch] $Fullscreen,
  [switch] $Hardened,
  [string] $Workspace
)

$ErrorActionPreference = 'Continue'

$root    = Split-Path -Parent $PSScriptRoot
$nodeExe = (Get-Command node -ErrorAction Stop).Source
$outLog  = Join-Path $PSScriptRoot 'run-seb.out.log'
$errLog  = Join-Path $PSScriptRoot 'run-seb.err.log'
$logFile = Join-Path $root 'run\log.txt'
$sessionFile = Join-Path $root 'run\session.json'
$sebExe  = 'C:\Program Files\SafeExamBrowser\Application\SafeExamBrowser.exe'

# SEB images, ordered child-first so the runtime exits before its parent.
$sebImages = @('CefSharp.BrowserSubprocess.exe', 'SafeExamBrowser.Client.exe', 'SafeExamBrowser.exe')

function Get-SebRuntime {
  @(Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $sebImages -contains "$($_.ProcessName).exe" })
}
function Get-RazorNodes {
  @(Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*main.mjs*' })
}

# --- preconditions -----------------------------------------------------------
if (-not (Test-Path $sebExe)) {
  Write-Host "  SafeExamBrowser.exe not found at $sebExe" -ForegroundColor Red
  exit 1
}

# Any razor left over from an earlier run would fight for the port.
foreach ($n in Get-RazorNodes) {
  Write-Host ("  cleaning up a previous razor node (pid {0})" -f $n.ProcessId) -ForegroundColor Yellow
  taskkill /PID $n.ProcessId /T /F | Out-Null
}

# Service baseline: remember whether it was already running.
$svcBefore = Get-Service -Name SafeExamBrowser -ErrorAction SilentlyContinue
$svcWasRunning = ($svcBefore -and $svcBefore.Status -eq 'Running')
$sebBefore = Get-SebRuntime
$sebVersion = (Get-Item $sebExe).VersionInfo.FileVersion

foreach ($f in @($outLog, $errLog, $logFile)) { if (Test-Path $f) { Remove-Item $f -Force } }
if (Test-Path $sessionFile) { Remove-Item $sessionFile -Force }

# --- environment -------------------------------------------------------------
$env:RAZOR_ENV        = 'dev'          # dev => allowQuit=true, plain .seb accepted
$env:RAZOR_ADMIN_PASS = 'devpass'
$env:RAZOR_LOG_FILE   = $logFile
$env:RAZOR_LEASE_MS   = '600000'       # outlive our window so the gate cannot lock early
$env:RAZOR_GRACE_MS   = '600000'
if ($Workspace) { $env:RAZOR_WORKSPACE = $Workspace }
Remove-Item Env:RAZOR_CONTROL_PLANE_URL -ErrorAction SilentlyContinue

# Hardened turns on createNewDesktop + killExplorerShell: a dedicated SEB desktop
# with Explorer out of the way. That is what actually stops window switching and
# closing, and it is incompatible with windowed view, so it implies fullscreen.
$effectiveFullscreen = $Fullscreen -or $Hardened
if ($effectiveFullscreen) { Remove-Item Env:RAZOR_SEB_WINDOWED -ErrorAction SilentlyContinue }
else { $env:RAZOR_SEB_WINDOWED = '1' }

if ($Hardened) { $env:RAZOR_SEB_HARDENED = '1' } else { Remove-Item Env:RAZOR_SEB_HARDENED -ErrorAction SilentlyContinue }

$nodeArgs = @('src/main.mjs', '--ui', 'dev', '--bypass-gate', '--seb')
if ($Port -gt 0) { $nodeArgs += @('--port', "$Port") }
if ($OpenBrowser) { $nodeArgs += '--open' }

Write-Host ''
Write-Host '  Razor + Safe Exam Browser timed run' -ForegroundColor Cyan
Write-Host ("  SEB version : {0}" -f $sebVersion)
$modeText = if ($Hardened) { 'HARDENED kiosk: dedicated desktop, Explorer shell killed' }
            elseif ($Fullscreen) { 'FULLSCREEN kiosk (still on your own desktop)' }
            else { 'windowed (easy escape)' }
Write-Host ("  SEB mode    : {0}" -f $modeText)
Write-Host ("  duration    : {0} minute(s), then forced quit" -f $Minutes)
Write-Host ("  SEB service : running={0} (left exactly as found on quit)" -f $svcWasRunning)
Write-Host ("  SEB running : {0} process(es) before launch" -f $sebBefore.Count)
Write-Host ("  audit log   : {0}" -f $logFile)
Write-Host ''
if ($Hardened) {
  Write-Host '  !! Your desktop is taken over for the whole run: the taskbar/shell goes away' -ForegroundColor Red
  Write-Host '  !! and this console is not reachable until the timer kills SEB. Ctrl+Alt+Del' -ForegroundColor Red
  Write-Host '  !! still works, and the run ends by itself -- do not panic-kill anything.' -ForegroundColor Red
  Write-Host ''
}

# --- launch ------------------------------------------------------------------
$proc = Start-Process -FilePath $nodeExe -ArgumentList $nodeArgs -WorkingDirectory $root `
                      -RedirectStandardOutput $outLog -RedirectStandardError $errLog `
                      -PassThru -WindowStyle Hidden

Write-Host ("  razor node pid {0}; waiting for the server, then SEB..." -f $proc.Id)

$deadline = (Get-Date).AddSeconds(45)
$origin = $null
$sebUp = $false
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Milliseconds 400
  if ($proc.HasExited) { break }
  if (-not $origin) {
    $text = [string](Get-Content $outLog -Raw -ErrorAction SilentlyContinue) + "`n" +
            [string](Get-Content $errLog -Raw -ErrorAction SilentlyContinue) + "`n" +
            [string](Get-Content $logFile -Raw -ErrorAction SilentlyContinue)
    $m = [regex]::Match($text, 'https?://127\.0\.0\.1:\d+')
    if ($m.Success) { $origin = $m.Value }
  }
  if ((Get-SebRuntime).Count -gt 0) { $sebUp = $true; if ($origin) { break } }
}

if ($proc.HasExited) {
  Write-Host '  Razor exited during startup:' -ForegroundColor Red
  Get-Content $outLog, $errLog -ErrorAction SilentlyContinue | Select-Object -Last 40
  exit 1
}

$sebNow = Get-SebRuntime
$listening = if ($origin) { Get-NetTCPConnection -State Listen -LocalPort ([uri]$origin).Port -ErrorAction SilentlyContinue } else { $null }

Write-Host ''
Write-Host ("  razor origin : {0}" -f $(if ($origin) { $origin } else { 'not reported yet' }))
Write-Host ("  listening    : {0}" -f $(if ($listening) { 'yes' } else { 'no' }))
Write-Host ("  SEB runtime  : {0} process(es) -- {1}" -f $sebNow.Count, (($sebNow | ForEach-Object { "$($_.ProcessName)($($_.Id))" }) -join ', '))
if (Test-Path $sessionFile) { Write-Host ("  session      : {0}" -f ((Get-Content $sessionFile -Raw).Trim() -replace '\s+', ' ')) }
Write-Host ''
if (-not $sebUp) { Write-Host '  WARNING: no SEB process appeared; check the SEB section of the log.' -ForegroundColor Yellow }
Write-Host ("  Quitting everything at {0}" -f (Get-Date).AddMinutes($Minutes).ToString('HH:mm:ss')) -ForegroundColor Yellow
Write-Host ''

# --- hold --------------------------------------------------------------------
Start-Sleep -Seconds ([int]([math]::Round($Minutes * 60)))

# --- quit: razor first, then SEB ---------------------------------------------
#
# Note on the two-step close: a plain `taskkill /PID <n> /T` (no /F) posts the
# close request to the console owner rather than delivering Ctrl+C to node, and
# Windows refuses to end a parent while its children are running. Measured here,
# it always failed with "can only be terminated forcefully" for every process in
# the tree. So the graceful pass gets one short attempt -- it costs nothing when
# the console does receive the close, which is the case when Razor is started
# interactively -- and the forced path is the one that actually has to work.
Write-Host ''
Write-Host '  --- quitting ---' -ForegroundColor Cyan
taskkill /PID $proc.Id /T 2>&1 | Out-Null
$proc.WaitForExit(4000) | Out-Null
if (-not $proc.HasExited) {
  Write-Host '  closing the razor process tree (forced)'
  taskkill /PID $proc.Id /T /F 2>&1 | Out-Null
  $proc.WaitForExit(8000) | Out-Null
}
Write-Host ("  razor node {0}: exited={1}" -f $proc.Id, $proc.HasExited)

# Now tear down SEB, child images first.
foreach ($img in $sebImages) {
  $hit = @(Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($img)) -ErrorAction SilentlyContinue)
  if ($hit.Count) {
    Write-Host ("  killing {0} x{1}" -f $img, $hit.Count)
    taskkill /IM $img /T /F 2>&1 | Out-Null
  }
}
Start-Sleep -Seconds 2

$sebAfter = Get-SebRuntime
# The CEF subprocess can linger a moment after its parent dies.
if ($sebAfter.Count) { Start-Sleep -Seconds 3; $sebAfter = Get-SebRuntime }

# --- service ----------------------------------------------------------------
$svc = Get-Service -Name SafeExamBrowser -ErrorAction SilentlyContinue
$svcAction = 'left running (was running before)'
if ($svc -and $svc.Status -eq 'Running' -and -not $svcWasRunning) {
  Write-Host '  stopping the SafeExamBrowser service (it was not running before this run)'
  Stop-Service -Name SafeExamBrowser -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 2
  $svc = Get-Service -Name SafeExamBrowser -ErrorAction SilentlyContinue
  $svcAction = "stopped (status=$($svc.Status))"
} elseif ($svc) {
  $svcAction = "left $($svc.Status) (matches the pre-run baseline)"
}

# --- verify -----------------------------------------------------------------
$razorLeft = Get-RazorNodes
$sebLeft = Get-SebRuntime
$portLeft = if ($origin) { Get-NetTCPConnection -State Listen -LocalPort ([uri]$origin).Port -ErrorAction SilentlyContinue } else { $null }

Write-Host ''
Write-Host '  --- verification ---' -ForegroundColor Cyan
Write-Host ("  SEB processes remaining : {0}" -f $sebLeft.Count)
Write-Host ("  SEB service             : {0}" -f $svcAction)
Write-Host ("  razor node remaining    : {0}" -f $razorLeft.Count)
Write-Host ("  port still listening    : {0}" -f [bool]$portLeft)

$clean = $sebLeft.Count -eq 0 -and $razorLeft.Count -eq 0 -and -not $portLeft -and $proc.HasExited
if ($clean) {
  Write-Host '  RESULT: Razor + SEB are fully quit; the desktop is yours again.' -ForegroundColor Green
} else {
  Write-Host '  RESULT: something survived -- see the counts above.' -ForegroundColor Red
}

if (Test-Path $logFile) {
  Write-Host ''
  Write-Host '  --- last razor log lines ---'
  Get-Content $logFile | Select-Object -Last 18
}
if (Test-Path $errLog) {
  $t = Get-Content $errLog | Select-Object -Last 8
  if ($t) { Write-Host '  --- last stderr ---'; $t }
}

exit $(if ($clean) { 0 } else { 1 })
