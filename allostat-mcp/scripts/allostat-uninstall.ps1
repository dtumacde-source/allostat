<#
.SYNOPSIS
  Uninstall Allostat - the in-terminal command (Windows).

  Removes THIS install's wrapper machinery and DISABLES Allostat for THIS
  surface only (Claude Code plugin + marketplace entry + MCP registration when
  run from the Claude install; config.toml block + standalone wrapper when run
  from the Codex install). Leaves ALL your data - memory, handoffs, .allostat
  state - and your ALLOSTAT_MCP_TOKEN untouched, so a reinstall resumes from
  where you left off.

  Run from any terminal:
    & "$env:USERPROFILE\.claude\plugins\marketplaces\local\allostat-mcp\scripts\allostat-uninstall.ps1"
    & "$env:USERPROFILE\.allostat\codex\allostat-mcp\scripts\allostat-uninstall.ps1"

  The actual removal logic lives in wrapper/lib/uninstall.py; this shim copies
  it (plus codex_wiring.py for the Codex surface) to a temp dir and runs it
  FROM there, so it can delete its own plugin directory without a Windows
  self-lock.
#>
$ErrorActionPreference = "Stop"

# Surface + removal library are derived ONLY from where THIS script lives
# (Sol P1-2/P2, operator requirement 2026-07-18). This shim ships in BOTH the
# Claude install (~\.claude\...) and the standalone Codex install
# (~\.allostat\codex\...). It must run ONLY its own install's removal code:
# never probe or execute the other surface's library (version skew there must
# not be able to break THIS uninstall), and ABORT when ownership can't be
# classified -- unknown ownership must never broaden into wider removal.
if ($PSScriptRoot -like "*\.allostat\codex\*") { $surface = "codex" }
elseif ($PSScriptRoot -like "*\.claude\*")     { $surface = "claude" }
else {
    Write-Host "Cannot determine which Allostat install owns this uninstaller:" -ForegroundColor Red
    Write-Host "  $PSScriptRoot" -ForegroundColor Red
    Write-Host "It is not under ~\.claude or ~\.allostat\codex. Nothing was removed."
    Write-Host "Run the copy inside the install you want to remove. To remove BOTH"
    Write-Host "installs, run each install's own uninstall script."
    exit 2
}

$pluginLib = Join-Path (Split-Path $PSScriptRoot -Parent) "lib"
if (-not (Test-Path (Join-Path $pluginLib "uninstall.py"))) {
    Write-Host "This install's removal logic is missing: $pluginLib\uninstall.py" -ForegroundColor Red
    Write-Host "Nothing was removed. Reinstall (or refresh) first, then uninstall."
    exit 1
}

# Resolve a Python interpreter (same order the installer prefers).
$python = $null
foreach ($cand in @("python", "python3", "py")) {
    $cmd = Get-Command $cand -ErrorAction SilentlyContinue
    if ($cmd) { $python = $cmd.Source; break }
}
if (-not $python) {
    Write-Error "No Python interpreter found on PATH - cannot run the uninstaller."
    exit 1
}

$tmp = Join-Path $env:TEMP ("allostat-uninstall-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    Copy-Item (Join-Path $pluginLib "uninstall.py") $tmp -Force
    # The Codex helper is only needed for the Codex surface (loaded lazily); a
    # Claude uninstall never imports it.
    if ($surface -eq "codex") {
        Copy-Item (Join-Path $pluginLib "codex_wiring.py") $tmp -Force
    }
    & $python (Join-Path $tmp "uninstall.py") "--surface" $surface
    $rc = $LASTEXITCODE
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
exit $rc
