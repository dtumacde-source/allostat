# allostat-doctor.ps1 -- Standalone Allostat MCP health check.
# PATCH-103.
#
# Read-only diagnostic tool. Does NOT modify any files or registry state.
# Use this to check whether Allostat is healthy without burning an install
# code or restarting Claude Code.
#
# Run from PowerShell:
#   & "$env:USERPROFILE\.claude\plugins\marketplaces\local\allostat-mcp\scripts\allostat-doctor.ps1"
#
# Flags:
#   -Verbose       Dump raw CLI outputs in addition to summary
#   -SkipCallable  Skip the authenticated tools/list probe (Layer 5).
#                  Useful when you don't want to make a network call.

param(
    [Parameter(Mandatory=$false)]
    [string]$ServerEndpoint = "https://mcp.allostat.ai",

    # -Verbose is a PowerShell common parameter and CAN'T be defined as
    # a custom param. Renamed to -Detail.
    [Parameter(Mandatory=$false)]
    [switch]$Detail,

    [Parameter(Mandatory=$false)]
    [switch]$SkipCallable
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "install-shared.ps1")

Write-Step "Allostat health check"
Write-Host ""

# Resolve required dependencies.
$claudeExe = Resolve-ClaudeExe
if (-not $claudeExe) {
    Write-Err "claude CLI not found on PATH or in known locations."
    Write-Host ""
    Write-Host "Status: cannot run health check without Claude Code installed."
    exit 5
}

# Bearer is optional for Layer 1-4 checks; only Layer 5 needs it.
$bearer = $null
if (-not $SkipCallable) {
    $bearer = Get-BearerFromEnvFile
    if (-not $bearer) {
        Write-Warn "Bearer not found in plugin .env -- skipping Layer 5 callable probe."
    }
}

# Run validation.
$validation = Invoke-FourLayerValidation `
    -ClaudeExe $claudeExe `
    -ServerEndpoint $ServerEndpoint `
    -Bearer $bearer `
    -SkipCallableProbe:($SkipCallable -or (-not $bearer))

# Pretty-print.
Format-StatusReport -Status $validation -ShowDetail:$Detail

# Exit with the validation's exit code (matches install_validation.py).
$exitCodeByState = @{
    "healthy"                       = 0
    "degraded_plugin_not_loaded"    = 1
    "degraded_mcp_not_registered"   = 2
    "degraded_mcp_failed_connect"   = 3
    "unreachable_server"            = 4
}

if ($exitCodeByState.ContainsKey($validation.state)) {
    exit $exitCodeByState[$validation.state]
}
exit 5
