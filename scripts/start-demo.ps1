# Run RedTeamGPT on this laptop for a demo.
#
#   powershell -ExecutionPolicy Bypass -File scripts\start-demo.ps1          # public https link
#   powershell -ExecutionPolicy Bypass -File scripts\start-demo.ps1 -Local   # this laptop only
#
# Public mode publishes a temporary https://<random>.trycloudflare.com link.
# Office networks often block it (Cloudflare Tunnel needs outbound port 7844);
# the script detects that and says so. Use -Local on such networks and share
# your screen instead - it needs no tunnel at all.
#
# For demos only: the app runs while this window is open and the laptop is
# awake. Data persists between runs in a Docker volume. Press Ctrl+C to stop.
#
# Needs: Docker Desktop running, the venv installed, models/detector-v6 with
# model.onnx, and cloudflared (default C:\dev\tools\cloudflared.exe).

param(
    [switch]$Local,
    [string]$Cloudflared = "C:\dev\tools\cloudflared.exe",
    [int]$Port = 7880,
    [int]$DbPort = 5434
)

# Not "Stop": in Windows PowerShell 5.1 that turns any stderr output from
# docker or python into a terminating error. Failures are checked explicitly.
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Python = Join-Path $Root "venv\Scripts\python.exe"
$EnvFile = Join-Path $Root ".env"
$TunnelLog = Join-Path $Root "logs\demo-tunnel.log"
New-Item -ItemType Directory -Force (Join-Path $Root "logs") | Out-Null

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }

# --- Pre-flight -------------------------------------------------------------
if (-not (Test-Path $Python)) { throw "venv not found at $Python" }
if (-not $Local -and -not (Test-Path $Cloudflared)) { throw "cloudflared not found at $Cloudflared" }
if (-not (Test-Path (Join-Path $Root "models\detector-v6\model.onnx"))) {
    throw "models\detector-v6\model.onnx is missing. Run: python src\export_onnx.py --model models\detector-v6"
}
function Test-Docker { docker info --format "{{.ServerVersion}}" 2>$null | Out-Null; return ($LASTEXITCODE -eq 0) }
if (-not (Test-Docker)) {
    # Machine-wide and per-user installs live in different places.
    $desktop = @(
        (Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\Docker Desktop.exe")
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $desktop) { throw "Docker is not running and Docker Desktop was not found. Start Docker and try again." }
    Step "Starting Docker Desktop (first start can take a minute or two)"
    Start-Process $desktop
    for ($i = 0; $i -lt 90 -and -not (Test-Docker); $i++) { Start-Sleep -Seconds 2 }
    if (-not (Test-Docker)) { throw "Docker Desktop did not start in 3 minutes. Open it manually, wait until it says 'Engine running', then run this again." }
}

# --- Encryption key (kept in .env so stored secrets survive restarts) -------
$envText = if (Test-Path $EnvFile) { Get-Content $EnvFile -Raw } else { "" }
$match = [regex]::Match($envText, "(?m)^DEMO_ENCRYPTION_KEY=(.+)$")
if ($match.Success) {
    $EncryptionKey = $match.Groups[1].Value.Trim()
} else {
    $bytes = New-Object byte[] 36
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $EncryptionKey = [Convert]::ToBase64String($bytes)
    Add-Content $EnvFile "`n# Encryption key for the laptop demo (scripts/start-demo.ps1). Do not change it.`nDEMO_ENCRYPTION_KEY=$EncryptionKey"
}

# --- Database ---------------------------------------------------------------
Step "Starting the database (Postgres in Docker)"
$exists = docker ps -a --filter "name=^rtg-demo-db$" --format "{{.Names}}"
if (-not $exists) {
    docker run -d --name rtg-demo-db -e POSTGRES_DB=redteamgpt -e POSTGRES_USER=rtg `
        -e POSTGRES_PASSWORD=rtg-demo-local -v rtg-demo-pgdata:/var/lib/postgresql/data `
        -p "127.0.0.1:${DbPort}:5432" postgres:16-alpine | Out-Null
} else {
    docker start rtg-demo-db | Out-Null
}
for ($i = 0; $i -lt 30; $i++) {
    docker exec rtg-demo-db pg_isready -U rtg 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { break }
    Start-Sleep -Seconds 2
}
Write-Host "    database ready"

# --- Public tunnel ----------------------------------------------------------
$tunnel = $null
if ($Local) {
    $PublicUrl = "http://localhost:$Port"
} else {
    Step "Opening the public link (Cloudflare Tunnel)"
    if (Test-Path $TunnelLog) { Remove-Item $TunnelLog }
    $tunnel = Start-Process -FilePath $Cloudflared -PassThru -WindowStyle Hidden `
        -ArgumentList "tunnel", "--no-autoupdate", "--protocol", "http2", "--url", "http://127.0.0.1:$Port" `
        -RedirectStandardError $TunnelLog
    # cloudflared prints the URL before it has actually connected, so wait for
    # a registered connection: a printed link on a blocked network is a dead link.
    $PublicUrl = $null; $connected = $false
    for ($i = 0; $i -lt 45 -and -not $connected; $i++) {
        Start-Sleep -Seconds 1
        if (Test-Path $TunnelLog) {
            $m = Select-String -Path $TunnelLog -Pattern "https://[a-z0-9-]+\.trycloudflare\.com" | Select-Object -First 1
            if ($m) { $PublicUrl = $m.Matches[0].Value }
            $connected = [bool](Select-String -Path $TunnelLog -Pattern "Registered tunnel connection" -Quiet)
        }
    }
    if (-not $connected) {
        Stop-Process -Id $tunnel.Id -Force -ErrorAction SilentlyContinue
        Write-Host ""
        Write-Host "  The public link could not connect. This network blocks Cloudflare Tunnel" -ForegroundColor Yellow
        Write-Host "  (common on office networks). Either:" -ForegroundColor Yellow
        Write-Host "    - switch to home Wi-Fi or a phone hotspot and run this again, or" -ForegroundColor Yellow
        Write-Host "    - run it with -Local and share your screen:" -ForegroundColor Yellow
        Write-Host "        powershell -ExecutionPolicy Bypass -File scripts\start-demo.ps1 -Local" -ForegroundColor Yellow
        Write-Host "  Details: $TunnelLog" -ForegroundColor Yellow
        exit 1
    }
}

# --- App --------------------------------------------------------------------
if ($Local) {
    # Production mode refuses a plain-http address (session cookies must be
    # Secure), so the local demo runs in development mode with the same
    # database, model and code.
    Step "Starting RedTeamGPT (local demo)"
    $env:ENVIRONMENT = "development"
} else {
    Step "Starting RedTeamGPT (production mode)"
    $env:ENVIRONMENT = "production"
}
$env:APP_BASE_URL = $PublicUrl
$env:DATABASE_URL = "postgresql://rtg:rtg-demo-local@127.0.0.1:${DbPort}/redteamgpt"
$env:ENCRYPTION_KEY = $EncryptionKey
$env:EMAIL_VERIFICATION_REQUIRED = "false"
$env:INFERENCE_BACKEND = "onnx"
$env:MODEL_DIR = "models/detector-v6"
$env:AUTO_MIGRATE = "true"
$env:LOG_JSON = "false"

# Open the browser once the app is actually ready.
Start-Process powershell -WindowStyle Hidden -ArgumentList "-NoProfile", "-Command", `
    "for (`$i=0; `$i -lt 120; `$i++) { try { Invoke-WebRequest -UseBasicParsing http://127.0.0.1:$Port/ready -TimeoutSec 2 | Out-Null; Start-Process '$PublicUrl'; break } catch { Start-Sleep 1 } }"

Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Green
if ($Local) {
    Write-Host "   Open on this laptop:  $PublicUrl" -ForegroundColor Green
    Write-Host "   Share your screen to show it. (Not reachable from other devices.)" -ForegroundColor Green
} else {
    Write-Host "   Share this link:  $PublicUrl" -ForegroundColor Green
    Write-Host "   (open it yourself too - sign-in only works on this link)" -ForegroundColor Green
}
Write-Host "   The browser opens by itself when ready (~30 s). Ctrl+C to stop." -ForegroundColor Green
Write-Host "  ============================================================" -ForegroundColor Green
Write-Host ""

try {
    # Bound to 127.0.0.1: only the tunnel can reach it, so trusting its
    # forwarded headers is safe.
    & $Python -m uvicorn backend.main:app --host 127.0.0.1 --port $Port `
        --proxy-headers --forwarded-allow-ips "127.0.0.1"
} finally {
    if ($tunnel) {
        Step "Stopping the public link"
        Stop-Process -Id $tunnel.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Host "    stopped. The database keeps running in Docker; it starts again next time."
}
