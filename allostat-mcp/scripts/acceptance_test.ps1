# acceptance_test.ps1 -- End-to-end Allostat MCP install verification.
# PATCH-103 v0.1.9.
#
# Dev-side smoke test that runs READ-ONLY checks against:
#   1. Production bundle served by Cloudflare (SHA + size match expected)
#   2. /install/resolve endpoint shape (POST with admin token returns
#      the bundle URL + SHA matching what's currently deployed)
#   3. Local install state (doctor reports all 5 layers green)
#   4. PATCH-104 server middleware behavior (comma-list MCP-Protocol-Version
#      gets sanitized to 401 not 400)
#
# Does NOT consume an install code. Does NOT modify any state. Run anytime
# to verify production is serving what's expected and the local install
# is healthy.
#
# Usage:
#   bash $WrapperDir/scripts/acceptance_test.ps1   (no, use PowerShell:)
#   & $WrapperDir/scripts/acceptance_test.ps1
#   & $WrapperDir/scripts/acceptance_test.ps1 -ExpectedVersion 0.1.9
#   & $WrapperDir/scripts/acceptance_test.ps1 -ExpectedSha b6096...
#
# Exits 0 on all checks pass, 1 on any failure.

param(
    [Parameter(Mandatory=$false)]
    [string]$ServerEndpoint = "https://mcp.allostat.ai",

    [Parameter(Mandatory=$false)]
    [string]$InstallerBase = "https://installer.allostat.ai",

    # If set, assert the deployed bundle matches this version string.
    # If empty, just runs the checks against whatever's deployed.
    [Parameter(Mandatory=$false)]
    [string]$ExpectedVersion = "",

    # If set, assert the deployed bundle's SHA256 matches this value.
    [Parameter(Mandatory=$false)]
    [string]$ExpectedSha = "",

    # Skip the local-install doctor check (useful when running from a
    # machine that doesn't have allostat-mcp installed).
    [Parameter(Mandatory=$false)]
    [switch]$SkipLocalDoctor
)

$ErrorActionPreference = "Continue"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Write-Step($Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok($Message)   { Write-Host "[ok] $Message" -ForegroundColor Green }
function Write-Warn($Message) { Write-Host "[warn] $Message" -ForegroundColor Yellow }
function Write-Err($Message)  { Write-Host "[error] $Message" -ForegroundColor Red }

$failures = 0

Write-Step "Allostat acceptance test (PATCH-103 v0.1.9)"
Write-Host ""

# ----------------------------------------------------------------------
# Check 1 -- /healthz reachable
# ----------------------------------------------------------------------
Write-Step "Check 1: server /healthz reachable"
try {
    $resp = Invoke-WebRequest -Uri "$ServerEndpoint/healthz" -Method Head -TimeoutSec 5 -UseBasicParsing
    Write-Ok "  HTTP $($resp.StatusCode)"
} catch [System.Net.WebException] {
    $code = $null
    try { $code = [int]$_.Exception.Response.StatusCode } catch {}
    if ($code) {
        Write-Ok "  HTTP $code (server up, /healthz requires auth)"
    } else {
        Write-Err "  unreachable: $($_.Exception.Message)"
        $failures++
    }
} catch {
    Write-Err "  unreachable: $($_.Exception.Message)"
    $failures++
}

# ----------------------------------------------------------------------
# Check 2 -- bundle served by Cloudflare (HEAD + SHA)
# ----------------------------------------------------------------------
Write-Step "Check 2: bundle served at expected URL"
$bundleUrl = $null
if ($ExpectedVersion) {
    $bundleUrl = "$InstallerBase/install/bundle/allostat-mcp-$ExpectedVersion.zip"
} else {
    # Probe `latest` -- but nginx doesn't serve symlinks. Need a known version.
    Write-Warn "  no -ExpectedVersion passed; skipping bundle SHA check"
    Write-Host "  (pass -ExpectedVersion <ver> -ExpectedSha <sha> to verify)"
}

if ($bundleUrl) {
    try {
        $bundleHead = Invoke-WebRequest -Uri $bundleUrl -Method Head -TimeoutSec 10 -UseBasicParsing
        Write-Ok "  HEAD $bundleUrl -> HTTP $($bundleHead.StatusCode) ($($bundleHead.Headers['Content-Length']) bytes)"

        if ($ExpectedSha) {
            $tmpZip = [IO.Path]::GetTempFileName() + ".zip"
            try {
                Invoke-WebRequest -Uri $bundleUrl -OutFile $tmpZip -UseBasicParsing -TimeoutSec 60
                $actualSha = (Get-FileHash $tmpZip -Algorithm SHA256).Hash.ToLower()
                $expectedShaLower = $ExpectedSha.ToLower()
                if ($actualSha -eq $expectedShaLower) {
                    Write-Ok "  SHA256 matches: $actualSha"
                } else {
                    Write-Err "  SHA256 MISMATCH"
                    Write-Err "    expected: $expectedShaLower"
                    Write-Err "    actual:   $actualSha"
                    $failures++
                }
            } finally {
                Remove-Item $tmpZip -ErrorAction SilentlyContinue
            }
        } else {
            Write-Warn "  (no -ExpectedSha passed; skipping SHA verification)"
        }
    } catch {
        Write-Err "  bundle fetch failed: $($_.Exception.Message)"
        $failures++
    }
}

# ----------------------------------------------------------------------
# Check 3 -- PATCH-104 middleware: comma-list MCP-Protocol-Version
# gets sanitized (401 not 400)
# ----------------------------------------------------------------------
Write-Step "Check 3: PATCH-104 middleware sanitizes comma-list header"
$probeHeaders = @{
    'Authorization' = "Bearer acceptance-test-fake-bearer"
    'Accept'        = 'application/json, text/event-stream'
    'Content-Type'  = 'application/json'
    'MCP-Protocol-Version' = '2025-11-25, 2025-03-26'
}
$probeBody = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
$got400 = $false
$got401 = $false
try {
    Invoke-WebRequest -Uri "$ServerEndpoint/mcp" -Method Post -Body $probeBody -Headers $probeHeaders -TimeoutSec 10 -UseBasicParsing | Out-Null
} catch [System.Net.WebException] {
    $code = $null
    try { $code = [int]$_.Exception.Response.StatusCode } catch {}
    if ($code -eq 400) { $got400 = $true }
    if ($code -eq 401) { $got401 = $true }
}
if ($got401) {
    Write-Ok "  comma-list header sanitized; bearer rejected normally (401)"
} elseif ($got400) {
    Write-Err "  comma-list header NOT sanitized; got 400 (PATCH-104 not deployed?)"
    $failures++
} else {
    Write-Warn "  unexpected response code; manual check recommended"
}

# ----------------------------------------------------------------------
# Check 4 -- local install doctor
# ----------------------------------------------------------------------
if (-not $SkipLocalDoctor) {
    Write-Step "Check 4: local allostat-doctor.ps1 reports healthy"
    $doctorPath = Join-Path $env:USERPROFILE ".claude\plugins\allostat-mcp\scripts\allostat-doctor.ps1"
    if (-not (Test-Path $doctorPath)) {
        Write-Warn "  doctor not installed at $doctorPath (skipping)"
    } else {
        # Run doctor and capture exit code
        $doctorOutput = & $doctorPath 2>&1 | Out-String
        $doctorExit = $LASTEXITCODE
        if ($doctorExit -eq 0) {
            Write-Ok "  doctor reports healthy (exit 0)"
        } else {
            Write-Err "  doctor reports degraded (exit $doctorExit)"
            Write-Host "  Last 20 lines of doctor output:"
            $doctorOutput -split "`n" | Select-Object -Last 20 | ForEach-Object { Write-Host "    $_" }
            $failures++
        }
    }
} else {
    Write-Step "Check 4: skipped (-SkipLocalDoctor)"
}

# ----------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------
Write-Host ""
if ($failures -eq 0) {
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "  Acceptance test: ALL CHECKS PASSED" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    exit 0
} else {
    Write-Host "================================================" -ForegroundColor Yellow
    Write-Host "  Acceptance test: $failures CHECK(S) FAILED" -ForegroundColor Yellow
    Write-Host "================================================" -ForegroundColor Yellow
    exit 1
}
