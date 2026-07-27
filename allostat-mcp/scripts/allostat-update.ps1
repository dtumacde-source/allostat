# allostat-update.ps1  --  code-free update for an existing install (S3 Leg 3b).
#
# Drives `/allostat update now`. Downloads the CURRENT install.ps1 from prod
# and runs it in -Refresh mode: install.ps1 uses the saved ALLOSTAT_MCP_TOKEN
# bearer against /install/refresh (no install code), verifies the bundle SHA,
# and stages the new version. Then the user restarts Claude Code (the E8
# version-skew banner reminds them).
#
# Fetch-fresh, like the installer exe: embeds no install logic, so it can't go
# stale. Windows-only for the soft-launch (a Mac/Linux code-free path is
# post-soft-launch). Single-source: all real work happens in install.ps1.

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.SecurityProtocolType]::Tls12 -bor [Net.ServicePointManager]::SecurityProtocol

$InstallPsUrl = "https://installer.allostat.ai/install/win/install.ps1"
$tmp = Join-Path $env:TEMP ("allostat-refresh-{0}.ps1" -f ([guid]::NewGuid().ToString('N')))

Write-Host "Checking for the latest Allostat version..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $InstallPsUrl -OutFile $tmp -UseBasicParsing -TimeoutSec 60
} catch {
    Write-Host "Could not download the installer: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$rc = 0
try {
    & $tmp -Refresh
    if ($null -ne $LASTEXITCODE) { $rc = $LASTEXITCODE }
} catch {
    Write-Host "Update failed: $($_.Exception.Message)" -ForegroundColor Red
    $rc = 1
} finally {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}

# Codex is a SEPARATE standalone install and updates ITSELF (operator
# requirement 2026-07-18, Sol P1-3): `python install/codex/install.py --refresh`
# at its own location, documented in the Codex INSTALL.md. This Claude updater
# never detects, reads, or refreshes the Codex install -- updating Claude must
# never affect Codex. Guarded by wrapper/tests/test_updater_claude_only.py.

if ($rc -eq 0) {
    Write-Host "Update staged. Fully quit and reopen Claude Code to load it." -ForegroundColor Green
}
exit $rc
