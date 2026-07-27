# repair-install.ps1 -- In-place repair for a degraded Allostat MCP install.
# PATCH-103.
#
# SCOPE: Config-drift on a successful install.
# NOT FOR: Failed/incomplete installs.
#
# If files are missing on disk OR the bundled bearer in .env is gone, this
# script cannot help. Re-run the full installer from your install email link.
#
# What it does (idempotent -- safe to re-run):
#   - Rewrites marketplace.json to canonical Zod-compliant shape
#   - Rewrites .mcp.json without MCP-Protocol-Version header
#   - Corrects installed_plugins.json "unknown" entries
#   - Re-runs `claude mcp remove + add --scope user` with the stored bearer
#   - Validates the install end-to-end (4 layers + optional tools/list probe)
#   - Prints a status report
#
# Run from PowerShell:
#   & "$env:USERPROFILE\.claude\plugins\marketplaces\local\allostat-mcp\scripts\repair-install.ps1"

param(
    [Parameter(Mandatory=$false)]
    [string]$ServerEndpoint = "https://mcp.allostat.ai",

    [Parameter(Mandatory=$false)]
    [switch]$SkipMcpAdd,

    # -Verbose is a PowerShell common parameter (every advanced
    # function gets it for free) and CAN'T be defined as a custom
    # param. Renamed to -Detail per PATCH-103 v0.1.8 lesson.
    [Parameter(Mandatory=$false)]
    [switch]$Detail
)

$ErrorActionPreference = "Stop"

# Dot-source the shared helper (this script lives next to it).
. (Join-Path $PSScriptRoot "install-shared.ps1")

Write-Step "Allostat MCP repair script (PATCH-103)"
Write-Host ""

# ----------------------------------------------------------------------
# Step 1 -- Resolve paths + verify plugin install is present.
# ----------------------------------------------------------------------

$claudeDir   = Get-ClaudeDir
$wrapperDir  = Get-PluginRoot

if (-not (Test-Path $claudeDir)) {
    Write-Err "Claude Code config dir not found at $claudeDir."
    Write-Host "Repair script can only run on a machine where Claude Code is installed."
    exit 1
}

if (-not (Test-Path $wrapperDir)) {
    Write-Err "Allostat MCP plugin dir not found at $wrapperDir."
    Write-Host ""
    Write-Host "Repair script is for FIXING a degraded install. There's nothing"
    Write-Host "to repair here -- run the full installer from your install email"
    Write-Host "link to do a fresh install."
    exit 1
}

# Detect the plugin version from plugin.json.
$pluginJsonPath = Join-Path $wrapperDir "plugin.json"
$pluginVersion = "unknown"
if (Test-Path $pluginJsonPath) {
    try {
        $pluginObj = Get-Content -Path $pluginJsonPath -Raw | ConvertFrom-Json
        if ($pluginObj.version) { $pluginVersion = $pluginObj.version }
    } catch {
        Write-Warn "Could not parse $pluginJsonPath -- continuing with version=unknown."
    }
}
Write-Ok "Plugin install detected at $wrapperDir (version $pluginVersion)"

# Detect the version cache dir (parallel install location).
$cacheBase = Join-Path $claudeDir "plugins\cache\local\allostat-mcp"
$versionCacheDir = Join-Path $cacheBase $pluginVersion
if (-not (Test-Path $versionCacheDir)) {
    # Try to find any version subdir
    $existingVersions = @()
    if (Test-Path $cacheBase) {
        $existingVersions = Get-ChildItem -Path $cacheBase -Directory -ErrorAction SilentlyContinue
    }
    if ($existingVersions.Count -gt 0) {
        $versionCacheDir = $existingVersions[0].FullName
        Write-Warn "Cache dir for $pluginVersion not found; using $versionCacheDir"
    }
}

# ----------------------------------------------------------------------
# Step 2 -- Resolve claude CLI.
# ----------------------------------------------------------------------

$claudeExe = Resolve-ClaudeExe
if (-not $claudeExe) {
    Write-Err "claude CLI not found on PATH or in known locations."
    Write-Host "Install Claude Code (or fix PATH), then re-run this repair script."
    exit 1
}
Write-Ok "claude CLI detected: $claudeExe"

# ----------------------------------------------------------------------
# Step 3 -- Read bearer from .env backup.
# ----------------------------------------------------------------------

$bearer = Get-BearerFromEnvFile -WrapperDir $wrapperDir
if (-not $bearer) {
    Write-Err "No bearer token found in $wrapperDir\.env."
    Write-Host ""
    Write-Host "Repair script needs the stored bearer to re-register the MCP"
    Write-Host "server. If .env is missing or the bearer was rotated, re-run"
    Write-Host "the full installer from your install email link."
    exit 1
}
Write-Ok "Bearer token read from .env backup"

# ----------------------------------------------------------------------
# Step 4 -- Rewrite marketplace.json to canonical shape.
# ----------------------------------------------------------------------

$marketplaceManifest = Join-Path $claudeDir "plugins\marketplaces\local\.claude-plugin\marketplace.json"
Write-Step "Rewriting marketplace.json (canonical Zod-compliant shape)..."
Write-CanonicalMarketplaceJson `
    -MarketplaceManifestPath $marketplaceManifest `
    -WrapperDir $wrapperDir `
    -Version $pluginVersion `
    -ClaudeDir $claudeDir
Write-Ok "marketplace.json rewritten"

# ----------------------------------------------------------------------
# Step 5 -- Rewrite .mcp.json without MCP-Protocol-Version.
# ----------------------------------------------------------------------

Write-Step "Cleaning up .mcp.json (removing MCP-Protocol-Version header)..."
foreach ($pluginDir in @($wrapperDir, $versionCacheDir)) {
    if (-not (Test-Path $pluginDir)) { continue }
    $mcpJsonPath = Join-Path $pluginDir ".mcp.json"
    # Audit #9 (2026-07-06): pass the recovered bearer so .mcp.json stores the
    # LITERAL token. Pre-fix repair omitted -Bearer, so Write-CleanMcpJson fell
    # back to the ${ALLOSTAT_MCP_TOKEN} env-var indirection PATCH-122 removed —
    # reintroducing the stale-process-env "MCP failing to connect" bug on any
    # long-open shell. The bearer was read + validated at Step 3.
    Write-CleanMcpJson `
        -McpJsonPath $mcpJsonPath `
        -ServerEndpoint $ServerEndpoint `
        -Version $pluginVersion `
        -Bearer $bearer
}
Write-Ok ".mcp.json rewritten"

# ----------------------------------------------------------------------
# Step 6 -- Correct installed_plugins.json "unknown" entries.
# ----------------------------------------------------------------------

Write-Step "Checking installed_plugins.json for 'unknown' entries..."
$repairResult = Repair-InstalledPluginsJson `
    -ClaudeDir $claudeDir `
    -VersionCacheDir $versionCacheDir `
    -Version $pluginVersion
if ($repairResult.changed) {
    Write-Ok "installed_plugins.json: $($repairResult.reason)"
} else {
    Write-Ok "installed_plugins.json: $($repairResult.reason)"
}

# ----------------------------------------------------------------------
# Step 7 -- Re-register MCP server via claude mcp add --scope user.
# ----------------------------------------------------------------------

if (-not $SkipMcpAdd) {
    Write-Step "Re-registering MCP server at user scope..."
    $addResult = Invoke-ClaudeMcpAdd `
        -ClaudeExe $claudeExe `
        -ServerEndpoint $ServerEndpoint `
        -Bearer $bearer
    if ($addResult.ok) {
        Write-Ok "MCP server registered at user scope"
    } else {
        Write-Warn "claude mcp add returned non-zero:"
        Write-Host $addResult.output
        Write-Host ""
        Write-Host "Continuing with validation anyway (registration may have partially succeeded)."
    }
}

# ----------------------------------------------------------------------
# Step 8 -- Validate.
# ----------------------------------------------------------------------

Write-Step "Running 4-layer validation..."
$validation = Invoke-FourLayerValidation `
    -ClaudeExe $claudeExe `
    -ServerEndpoint $ServerEndpoint `
    -Bearer $bearer

if ($Detail) {
    Format-StatusReport -Status $validation -ShowDetail
} else {
    Format-StatusReport -Status $validation
}

# ----------------------------------------------------------------------
# Final message
# ----------------------------------------------------------------------

if ($validation.ok) {
    Write-Host "Repair complete. Restart Claude Code to pick up the rewritten" -ForegroundColor Green
    Write-Host "configuration (close ALL Claude Code windows + reopen)." -ForegroundColor Green
    Write-Host ""
    exit 0
} else {
    Write-Host "Repair incomplete -- some layers still failing." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "If the issue persists, re-run the full installer from your" -ForegroundColor Yellow
    Write-Host "install email link with a fresh code." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}
