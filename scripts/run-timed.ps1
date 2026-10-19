<#
  run-timed.ps1 -- launch Razor IDE, hold it open for a fixed time, then QUIT it.

  Why this exists: the Razor server has no self-timer and no HTTP/CLI "shutdown"
  command (main.mjs only exits on SIGINT/SIGTERM or a fatal error). Without a
  wrapper you would have to close the window yourself, and a half-killed run
  leaves the IDE server holding its port.

  What it does:
    1. starts `node src/main.mjs` detached with its own console
    2. reads the ephemeral port back out of run/log.txt (or run/session.json)
    3. optionally opens the start URL in your default browser
    4. waits N minutes
    5. asks the process tree to close (WM_CLOSE / CTRL event -> SIGINT path in
       main.mjs: gate.stop(), terminal.kill(), server.close(), audit.close())
    6. escalates to `taskkill /T /F` if it is still alive 8s later
    7. verifies no razor node process and no listener on the port remain

  Usage:
    pwsh -File scripts/run-timed.ps1                    # 1 minute, dev, unlocked
    pwsh -File scripts/run-timed.ps1 -Minutes 5
    pwsh -File scripts/run-timed.ps1 -Minutes 2 -OpenBrowser
    pwsh -File scripts/run-timed.ps1 -Minutes 2 -Seb -Windowed   # SEB, escapable
#>
[CmdletBinding()]
param(
  [double] $Minutes = 1,
  [int]    $Port = 0,
  [switch] $OpenBrowser,
  [switch] $Seb,
  [switch] $Windowed,
  [string] $Workspace
)

$ErrorActionPreference = 'Stop'

$root    = Split-Path -Parent $PSScriptRoot
$nodeExe = (Get-Command node -ErrorAction Stop).Source
$outLog  = Join-Path $PSScriptRoot 'run-timed.out.log'
$errLog  = Join-Path $PSScriptRoot 'run-timed.err.log'
$logFile = Join-Path $root 'run\log.txt'
$sessionFile = Join-Path $root 'run\session.json'

# Razor appends structured logs here; Start-Process cannot append, so truncate.
foreach ($f in @($outLog, $errLog, $logFile)) { if (Test-Path $f) { Remove-Item $f -Force } }
if (Test-Path $sessionFile) { Remove-Item $sessionFile -Force }

# --- environment: dev security mode, unlocked gate, no control plane ---------
$env:RAZOR_ENV           = 'dev'
$env:RAZOR_ADMIN_PASS    = 'devpass'
$env:RAZOR_LOG_FILE      = $logFile
$env:RAZOR_LEASE_MS      = '600000'   # keep the session lease alive past our window
$env:RAZOR_GRACE_MS      = '600000'
if ($Workspace) { $env:RAZOR_WORKSPACE = $Workspace }
if ($Windowed)  { $env:RAZOR_SEB_WINDOWED = '1' }   # allowQuit=true: easy escape hatch
Remove-Item Env:RAZOR_CONTROL_PLANE_URL -ErrorAction SilentlyContinue

$nodeArgs = @('src/main.mjs', '--ui', 'dev', '--bypass-gate')
if ($Port -gt 0) { $nodeArgs += @('--port', "$Port") }
if ($OpenBrowser) { $nodeArgs += '--open' }
if ($Seb) { $nodeArgs += '--seb' }

Write-Host ''
Write-Host '  Razor timed run' -ForegroundColor Cyan
Write-Host ("  requested   : {0} minute(s), then forced quit" -f $Minutes)
Write-Host ("  security    : dev (gate bypassed via --bypass-gate)")
Write-Host ("  safe exam b.: {0}" -f $(if ($Seb) { 'YES (kiosk)' } else { 'no' }))
Write-Host ("  audit log   : {0}" -f $logFile)
Write-Host ''

$proc = Start-Process -FilePath $nodeExe -ArgumentList $nodeArgs -WorkingDirectory $root `
                      -RedirectStandardOutput $outLog -RedirectStandardError $errLog `
                      -PassThru -WindowStyle Hidden

Write-Host ("  node pid {0} started; waiting for the listen banner..." -f $proc.Id)

# --- wait for the server to report its origin --------------------------------
$origin = $null
$deadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $deadline -and -not $origin) {
  Start-Sleep -Milliseconds 300
  if ($proc.HasExited) { break }
  $text = [string](Get-Content $outLog -Raw -ErrorAction SilentlyContinue) + "`n" +
          [string](Get-Content $errLog -Raw -ErrorAction SilentlyContinue) + "`n" +
          [string](Get-Content $logFile -Raw -ErrorAction SilentlyContinue)
  $m = [regex]::Match($text, 'https?://127\.0\.0\.1:\d+')
  if ($m.Success) { $origin = $m.Value }
}

if ($proc.HasExited) {
  Write-Host '  Razor exited during startup. Output follows:' -ForegroundColor Red
  Get-Content $outLog -ErrorAction SilentlyContinue | Select-Object -Last 40
  Get-Content $errLog -ErrorAction SilentlyContinue | Select-Object -Last 40
  exit 1
}
if (-not $origin) {
  Write-Host '  Server did not report an origin in 30s; aborting and cleaning up.' -ForegroundColor Red
  Get-Content $outLog -ErrorAction SilentlyContinue | Select-Object -Last 40
  Get-Content $errLog -ErrorAction SilentlyContinue | Select-Object -Last 40
  taskkill /PID $proc.Id /T /F | Out-Null
  exit 1
}

$listening = Get-NetTCPConnection -State Listen -LocalPort ([uri]$origin).Port -ErrorAction SilentlyContinue
Write-Host ''
Write-Host ("  RUNNING  ->  {0}" -f $origin) -ForegroundColor Green
Write-Host ("  listening: {0}" -f $(if ($listening) { 'yes' } else { 'NOT VERIFIED' }))
if (Test-Path $sessionFile) {
  Write-Host ("  session  : {0}" -f ((Get-Content $sessionFile -Raw).Trim() -replace '\s+', ' '))
}
Write-Host ''
Write-Host ("  It will quit by itself at {0}" -f (Get-Date).AddMinutes($Minutes).ToString('HH:mm:ss')) -ForegroundColor Yellow
Write-Host ''

# --- hold, then quit ---------------------------------------------------------
Start-Sleep -Seconds ([int]([math]::Round($Minutes * 60)))

Write-Host ''
Write-Host '  --- quitting ---' -ForegroundColor Cyan
$alive = -not $proc.HasExited
if ($alive) {
  # Graceful: WM_CLOSE to the console window -> node's SIGINT path.
  taskkill /PID $proc.Id /T | Out-Null
  $proc.WaitForExit(8000) | Out-Null
}
if (-not $proc.HasExited) {
  Write-Host '  graceful close did not take; forcing the process tree' -ForegroundColor Yellow
  taskkill /PID $proc.Id /T /F | Out-Null
  $proc.WaitForExit(5000) | Out-Null
}

Start-Sleep -Milliseconds 800

# --- verify: nothing of ours is left ----------------------------------------
$leftover = @(Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -like '*src/main.mjs*' -or $_.CommandLine -like '*razor*' })
$stillListening = Get-NetTCPConnection -State Listen -LocalPort ([uri]$origin).Port -ErrorAction SilentlyContinue
$sebLeft = @(Get-Process -Name 'SafeExamBrowser*' -ErrorAction SilentlyContinue)

Write-Host ''
Write-Host ("  node pid {0} exited: {1}" -f $proc.Id, $proc.HasExited)
Write-Host ("  razor node processes left : {0}" -f $leftover.Count)
Write-Host ("  port {0} still listening    : {1}" -f ([uri]$origin).Port, [bool]$stillListening)
if ($Seb) { Write-Host ("  SEB processes left        : {0}" -f $sebLeft.Count) }

$clean = $proc.HasExited -and $leftover.Count -eq 0 -and -not $stillListening
if ($clean) {
  Write-Host '  RESULT: Razor is fully quit.' -ForegroundColor Green
} else {
  Write-Host '  RESULT: something survived -- see the counts above.' -ForegroundColor Red
}

if (Test-Path $logFile) {
  Write-Host ''
  Write-Host '  --- last log lines ---'
  Get-Content $logFile | Select-Object -Last 15
}
if (Test-Path $errLog) {
  $errTail = Get-Content $errLog | Select-Object -Last 10
  if ($errTail) { Write-Host '  --- last stderr lines ---'; $errTail }
}

exit $(if ($clean) { 0 } else { 1 })
