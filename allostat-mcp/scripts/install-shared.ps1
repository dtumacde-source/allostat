# install-shared.ps1 -- Shared PowerShell helpers for Allostat MCP installer,
# repair script, and health-check tool. PATCH-103.
#
# Three callers dot-source this file:
#   1. install.ps1            (in allostat-server bundle; dot-sources AFTER
#                              Step 7 extracts this bundle and the helper
#                              becomes available on disk)
#   2. repair-install.ps1     (in this bundle; config-drift fix without
#                              re-downloading)
#   3. allostat-doctor.ps1    (in this bundle; standalone health check)
#
# Conventions:
#   - All functions use approved-verb PowerShell naming (Test-, Write-,
#     Invoke-, Repair-, Resolve-, Get-, Format-).
#   - No operator-specific paths baked in. Paths are resolved from
#     $env:USERPROFILE / $PSScriptRoot / parameters at call time.
#   - Functions return structured PSCustomObjects when they have multiple
#     outputs; simple booleans or strings when they have one.
#   - Console output uses Write-Step / Write-Ok / Write-Warn / Write-Err
#     for consistent operator-facing messaging across all three callers.

# ----------------------------------------------------------------------
# Console output helpers
# ----------------------------------------------------------------------

function Write-Step($Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok($Message)   { Write-Host "[ok] $Message" -ForegroundColor Green }
function Write-Warn($Message) { Write-Host "[warn] $Message" -ForegroundColor Yellow }
function Write-Err($Message)  { Write-Host "[error] $Message" -ForegroundColor Red }

# ----------------------------------------------------------------------
# Write-Utf8NoBom -- UTF-8 without BOM file write.
#
# PS 5.1's `Set-Content -Encoding UTF8` writes a BOM, which Claude Code's
# marketplace + plugin loaders reject. This helper writes the same
# encoding the loaders expect across both PS 5.1 and PS 7+.
# ----------------------------------------------------------------------

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory=$true)] [string]$Path,
        [Parameter(Mandatory=$true)] [string]$Content
    )
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

# ----------------------------------------------------------------------
# Resolve-RealPython -- Find a real CPython interpreter on PATH.
#
# Windows ships a Microsoft Store stub at
# %LOCALAPPDATA%\Microsoft\WindowsApps\python.exe that intercepts bare
# `python` invocations and opens the Store. The hook scripts need the
# real CPython. Returns the absolute path string, or $null if none found.
# ----------------------------------------------------------------------

function Resolve-RealPython {
    $candidates = Get-Command python.exe -All -ErrorAction SilentlyContinue
    foreach ($c in $candidates) {
        if ($c.Source -and $c.Source -notmatch 'WindowsApps') {
            return $c.Source
        }
    }
    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($py -and $py.Source -notmatch 'WindowsApps') {
        return $py.Source
    }
    return $null
}

# ----------------------------------------------------------------------
# Resolve-ClaudeExe -- Find the claude CLI binary across known locations.
#
# Returns the absolute path string, or $null if not found.
# ----------------------------------------------------------------------

function Resolve-ClaudeExe {
    $candidates = @(
        (Join-Path $env:USERPROFILE ".local\bin\claude.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Claude Code\claude.exe"),
        (Join-Path $env:LOCALAPPDATA "AnthropicClaude\claude.exe"),
        (Join-Path $env:APPDATA "npm\claude.cmd")
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    $onPath = Get-Command claude -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    return $null
}

# ----------------------------------------------------------------------
# Get-PluginRoot -- Canonical path to the allostat-mcp plugin runtime dir.
#
# PATCH-106 deploy-model shift: the plugin must live INSIDE the local
# marketplace directory (`~/.claude/plugins/marketplaces/local/`) — NOT
# as a sibling of the marketplaces/ dir — because Claude Code's plugin
# loader resolves `marketplace.json::plugins[].source` as a path RELATIVE
# to the marketplace root. The pre-PATCH-106 sibling deploy + object-form
# source (`{type:"local", path:<absolute>}`) is rejected at load time by
# the schema validator (every fresh v0.1.x install hit Layer 1 failure).
#
# The runtime dir is where Claude Code's hook-discovery looks for
# hooks/hooks.json. NOT the cache dir (that's the version-pinned
# source-of-truth for the install run, but Claude Code reads runtime
# from the marketplace subdir).
# ----------------------------------------------------------------------

function Get-PluginRoot {
    return (Join-Path $env:USERPROFILE ".claude\plugins\marketplaces\local\allostat-mcp")
}

# ----------------------------------------------------------------------
# Get-LegacyPluginRoot -- Pre-PATCH-106 sibling path.
#
# Returned for upgrade-path detection only. If this exists on a machine
# undergoing a v0.1.11+ install, the installer surfaces a cleanup notice
# + removes it after the new install lands (operator state in .env is
# preserved through a backup step before removal).
# ----------------------------------------------------------------------

function Get-LegacyPluginRoot {
    return (Join-Path $env:USERPROFILE ".claude\plugins\allostat-mcp")
}

# ----------------------------------------------------------------------
# Get-ClaudeDir -- Default Claude Code config directory.
# ----------------------------------------------------------------------

function Get-ClaudeDir {
    return (Join-Path $env:USERPROFILE ".claude")
}

# ----------------------------------------------------------------------
# Get-MarketplaceRoot -- Path to the local marketplace dir.
#
# The plugin lives at $MarketplaceRoot/allostat-mcp/ per PATCH-106. The
# marketplace.json manifest lives at $MarketplaceRoot/.claude-plugin/.
# ----------------------------------------------------------------------

function Get-MarketplaceRoot {
    return (Join-Path $env:USERPROFILE ".claude\plugins\marketplaces\local")
}

# ----------------------------------------------------------------------
# Test-PreFlightChecks (advisor §2 flag #2 option c)
#
# Run BEFORE /install/resolve (Step 4) so install-time failures don't
# burn the user's install code without delivering anything. Each check
# is non-destructive and fast.
#
# Checks:
#   - Claude Code installed (~/.claude/ exists, claude CLI on PATH)
#   - Real Python interpreter (not Microsoft Store stub)
#   - Sufficient disk space (>= 50 MB at ~/.claude/plugins/)
#   - Network reachable (HTTPS connectivity to mcp.allostat.ai)
#
# Returns a PSCustomObject with .ok bool + .failures array of strings.
# ----------------------------------------------------------------------

function Test-PreFlightChecks {
    param(
        [string]$ServerEndpoint = "https://mcp.allostat.ai",
        [int]$MinFreeMb = 50
    )

    $failures = @()
    $detail = [ordered]@{}

    # Check 1 -- Claude Code config dir exists
    $claudeDir = Get-ClaudeDir
    if (-not (Test-Path $claudeDir)) {
        $failures += "Claude Code not detected at $claudeDir. Install Claude Code first from https://claude.com/claude-code"
    }
    $detail.claude_dir_exists = (Test-Path $claudeDir)

    # Check 2 -- claude CLI on PATH
    $claudeExe = Resolve-ClaudeExe
    if (-not $claudeExe) {
        $failures += "claude CLI not found on PATH or in known install locations. Make sure Claude Code is installed and on PATH, then re-run."
    }
    $detail.claude_exe = $claudeExe

    # Check 3 -- real Python interpreter
    $pythonPath = Resolve-RealPython
    if (-not $pythonPath) {
        $failures += "No real Python interpreter found (Microsoft Store stub doesn't count). Install CPython 3.10+ from https://www.python.org/downloads/"
    }
    $detail.python_path = $pythonPath

    # Check 4 -- disk space at ~/.claude/plugins/
    try {
        $pluginsParent = Join-Path $env:USERPROFILE ".claude"
        if (Test-Path $pluginsParent) {
            $driveLetter = (Get-Item $pluginsParent).PSDrive.Name
            $drive = Get-PSDrive -Name $driveLetter -ErrorAction Stop
            $freeMb = [math]::Floor($drive.Free / 1MB)
            $detail.free_disk_mb = $freeMb
            if ($freeMb -lt $MinFreeMb) {
                $failures += "Insufficient disk space on drive ${driveLetter}: ${freeMb}MB free, need at least ${MinFreeMb}MB. Free up space and re-run."
            }
        } else {
            $detail.free_disk_mb = $null
        }
    } catch {
        $detail.free_disk_mb = $null
        # Don't fail on disk check error -- it's a probe, not a hard requirement.
    }

    # Check 5 -- network reachable to server endpoint
    try {
        $netResponse = Invoke-WebRequest `
            -Uri "$ServerEndpoint/healthz" `
            -Method Head `
            -TimeoutSec 5 `
            -UseBasicParsing `
            -ErrorAction SilentlyContinue
        $detail.server_reachable = ($netResponse -and $netResponse.StatusCode -lt 500)
    } catch [System.Net.WebException] {
        # 4xx counts as reachable (server responded)
        $statusCode = $null
        try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        if ($statusCode -and $statusCode -lt 500) {
            $detail.server_reachable = $true
        } else {
            $detail.server_reachable = $false
            $failures += "Network check failed: cannot reach $ServerEndpoint/healthz. Check internet connection."
        }
    } catch {
        $detail.server_reachable = $false
        $failures += "Network check failed: cannot reach $ServerEndpoint/healthz. Check internet connection."
    }

    return [pscustomobject]@{
        ok = ($failures.Count -eq 0)
        failures = $failures
        detail = $detail
    }
}

# ----------------------------------------------------------------------
# Write-CanonicalMarketplaceJson -- Zod-compliant marketplace.json writer.
#
# PATCH-106 fix: emit `source` as a BARE STRING relative to the
# marketplace root, NOT the pre-patch object form `{type:"local", path:<abs>}`.
# Claude Code's plugin-loader schema rejects the object form for local
# sibling plugins; only object-form `source.source:"url"|"git-subdir"`
# (both git-derived schemes) and bare-string relative paths to a SUBDIR
# of the marketplace are accepted. Empirical verification on operator
# PC 2026-05-17: 3 hypotheses with sibling plugin failed; 4th hypothesis
# (plugin COPIED into marketplace dir + bare-string `./allostat-mcp`
# source) is the only working configuration.
#
# v2.3 allostat plugin coexistence dropped from marketplace.json. The
# v0.1.x install path disables v2.3 via settings.json enabledPlugins,
# so including it in the marketplace.json would re-introduce the same
# class of bug (sibling plugin + invalid schema) for no operator benefit.
# v2.3 users transitioning to v0.1.x get the wrapper as primary; v2.3
# can stay on disk but is no longer in the local marketplace manifest.
# ----------------------------------------------------------------------

function Write-CanonicalMarketplaceJson {
    param(
        [Parameter(Mandatory=$true)] [string]$MarketplaceManifestPath,
        [Parameter(Mandatory=$false)] [string]$WrapperDir,   # accepted for legacy compatibility; unused post-PATCH-106
        [Parameter(Mandatory=$true)] [string]$Version,
        [string]$ClaudeDir = $null
    )

    if (-not $ClaudeDir) { $ClaudeDir = Get-ClaudeDir }

    # Ensure parent dir exists.
    $parent = Split-Path $MarketplaceManifestPath -Parent
    if (-not (Test-Path $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    # The Allostat plugin entry we own and always (re)write. PATCH-106:
    # bare-string relative source resolving to a SUBDIR of the marketplace root
    # (i.e., $MarketplaceRoot/allostat-mcp/). The plugin MUST be deployed at that
    # subdir for the loader to find it.
    $allostatEntry = [pscustomobject]@{
        name = "allostat-mcp"
        description = "Hosted-MCP wrapper for Allostat. Thin Claude Code plugin that routes hook events to the regulator brain at mcp.allostat.ai while keeping all operator memory client-side."
        source = "./allostat-mcp"
        version = $Version
    }

    # Audit #7 (2026-07-06): UPSERT, don't clobber. Pre-fix this function
    # deleted marketplace.json and wrote an Allostat-only manifest, silently
    # dropping every co-resident third-party plugin an operator had in their
    # local marketplace. Now we read the existing manifest, preserve its
    # top-level metadata and all UNRELATED plugins[] entries, and upsert only
    # the allostat-mcp entry. Invariant #4: detect-before-write, never destroy
    # operator files.
    $otherPlugins = @()
    $topName = "local"
    $topDescription = "Local plugin marketplace for Allostat (operator-developed Claude Code plugins). Maintained on disk; not synced from any remote source."
    $topOwner = [pscustomobject]@{
        name = "Allostat"
        email = "support@allostat.ai"
    }

    if (Test-Path $MarketplaceManifestPath) {
        # Timestamped backup before any rewrite (operator-file safety).
        try {
            $stamp = Get-Date -Format "yyyyMMddTHHmmss"
            Copy-Item -Path $MarketplaceManifestPath -Destination "$MarketplaceManifestPath.$stamp.bak" -Force -ErrorAction SilentlyContinue
        } catch { }

        try {
            $existing = Get-Content -Path $MarketplaceManifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ($existing) {
                if ($existing.name)        { $topName = $existing.name }
                if ($existing.description) { $topDescription = $existing.description }
                if ($existing.owner)       { $topOwner = $existing.owner }
                if ($existing.plugins) {
                    # Preserve every entry except the ones we manage: allostat-mcp
                    # (upserted below) and the legacy v2.3 `allostat` entry, which
                    # PATCH-106 deliberately excludes (invalid sibling schema).
                    $otherPlugins = @($existing.plugins | Where-Object {
                        $_.name -ne "allostat-mcp" -and $_.name -ne "allostat"
                    })
                }
            }
        } catch {
            # Malformed existing manifest: the .bak above preserves it; fall
            # through to a clean Allostat-only manifest rather than crash the
            # install.
            Write-Warning "marketplace.json unreadable ($($_.Exception.Message)); writing fresh manifest (backup kept)."
            $otherPlugins = @()
        }
    }

    # allostat-mcp last so its (re)written entry is deterministic; order of
    # other entries is preserved as-read.
    $pluginEntries = @($otherPlugins + $allostatEntry)

    $marketplace = [pscustomobject]@{
        name = $topName
        description = $topDescription
        owner = $topOwner
        plugins = $pluginEntries
    }

    Write-Utf8NoBom -Path $MarketplaceManifestPath -Content ($marketplace | ConvertTo-Json -Depth 6)
}

# ----------------------------------------------------------------------
# Protect-CredentialFile -- owner-only ACL or no credential file.
# ----------------------------------------------------------------------

function Set-CredentialAcl {
    # The single point where a DACL is applied. Exists so the ACL-ordering
    # tests can spy on OUR seam instead of a Windows cmdlet: hooking `Set-Acl`
    # silently stopped working the moment the DACL-only fix switched to
    # SetAccessControl, and eleven tests went blind rather than red.
    param(
        [Parameter(Mandatory=$true)] [string]$LiteralPath,
        [Parameter(Mandatory=$true)] [object]$AclObject
    )
    $target = Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
    $target.SetAccessControl($AclObject)
}

function Protect-CredentialFile {
    param(
        [Parameter(Mandatory=$true)] [string]$Path,
        [switch]$PreserveOnFailure
    )

    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "credential file does not exist"
        }
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (
            ($item.Attributes -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw "credential file must not be a reparse point"
        }
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        if (-not $sid) { throw "current user SID is unavailable" }

        # DACL-ONLY (2026-07-27). Get-Acl/Set-Acl covers more than the DACL,
        # and once the DACL is PROTECTED — the state the first install leaves —
        # Set-Acl needs SeSecurityPrivilege, which a normal user lacks. That made
        # the first install succeed and every UPDATE fail. GetAccessControl/
        # SetAccessControl scoped to Access needs only WRITE_DAC, held by the owner.
        $aclItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $acl = $aclItem.GetAccessControl(
            [System.Security.AccessControl.AccessControlSections]::Access)
        $acl.SetAccessRuleProtection($true, $false)
        $existing = @($acl.GetAccessRules(
            $true,
            $false,
            [System.Security.Principal.SecurityIdentifier]
        ))
        foreach ($rule in $existing) {
            [void]$acl.RemoveAccessRuleSpecific($rule)
        }
        $ownerRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($ownerRule)
        Set-CredentialAcl -LiteralPath $Path -AclObject $acl

        $verifiedItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $verified = (Get-Item -LiteralPath $Path -Force -ErrorAction Stop).GetAccessControl(
            [System.Security.AccessControl.AccessControlSections]::Access)
        $rules = @($verified.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]
        ))
        $full = [System.Security.AccessControl.FileSystemRights]::FullControl
        if (
            ($verifiedItem.Attributes -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $verified.AreAccessRulesProtected -or
            $rules.Count -ne 1 -or
            $rules[0].IsInherited -or
            $rules[0].IdentityReference.Value -ne $sid.Value -or
            $rules[0].AccessControlType -ne
                [System.Security.AccessControl.AccessControlType]::Allow -or
            ($rules[0].FileSystemRights -band $full) -ne $full
        ) {
            throw "owner-only ACL verification failed"
        }
    } catch {
        if (-not $PreserveOnFailure) {
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        }
        throw "Could not protect credential file $Path : $($_.Exception.Message)"
    }
}

# Persist UTF-8 credential text only after the target has a verified owner-only
# ACL. Existing recovery content is preserved if hardening fails. New targets
# are created empty with CreateNew, then protected before any secret bytes land.
function Write-ProtectedCredentialFile {
    param(
        [Parameter(Mandatory=$true)] [string]$Path,
        [Parameter(Mandatory=$true)] [string]$Content
    )

    $createdNew = $false
    try {
        if (Test-Path -LiteralPath $Path) {
            $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
            if (
                ($item.Attributes -band
                    [System.IO.FileAttributes]::ReparsePoint) -ne 0
            ) {
                throw "credential target must not be a reparse point"
            }
            if ($item.PSIsContainer) {
                throw "credential target is not a file"
            }
        } else {
            $stream = $null
            try {
                $stream = [System.IO.File]::Open(
                    $Path,
                    [System.IO.FileMode]::CreateNew,
                    [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::None
                )
            } finally {
                if ($null -ne $stream) { $stream.Dispose() }
            }
            $createdNew = $true
        }

        if ($createdNew) {
            Protect-CredentialFile -Path $Path
        } else {
            Protect-CredentialFile -Path $Path -PreserveOnFailure
        }

        $verifiedItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (
            ($verifiedItem.Attributes -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw "credential target became a reparse point before write"
        }
        if ($verifiedItem.PSIsContainer) {
            throw "credential target is not a file"
        }

        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
    } catch {
        $failureMessage = $_.Exception.Message
        if ($createdNew -and (Test-Path -LiteralPath $Path -PathType Leaf)) {
            try {
                $failedItem = Get-Item -LiteralPath $Path -Force `
                    -ErrorAction Stop
                if (
                    ($failedItem.Attributes -band
                        [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
                    $failedItem.Length -eq 0
                ) {
                    Remove-Item -LiteralPath $Path -Force `
                        -ErrorAction SilentlyContinue
                }
            } catch { }
        }
        throw "Could not write protected credential file $Path : $failureMessage"
    }
}

# ----------------------------------------------------------------------
# Write-CleanMcpJson -- Write .mcp.json WITHOUT MCP-Protocol-Version.
#
# PC-Claude's brief 2026-05-16 (Bug 2): Claude Code CLI always sets its
# own MCP-Protocol-Version header. A user-supplied duplicate appends
# rather than replaces, producing a comma-joined value the server's
# strict parser rejects. Solution: REMOVE the header from .mcp.json.
# ----------------------------------------------------------------------

function Write-CleanMcpJson {
    param(
        [Parameter(Mandatory=$true)] [string]$McpJsonPath,
        [Parameter(Mandatory=$true)] [string]$ServerEndpoint,
        [Parameter(Mandatory=$true)] [string]$Version,
        [Parameter(Mandatory=$false)] [string]$Bearer = $null
    )

    # v0.2.1 PATCH-122: write LITERAL bearer instead of ${ALLOSTAT_MCP_TOKEN}.
    #
    # The env-var indirection caused "MCP failing to connect" on every
    # upgrade because:
    #   1. Installer rotates the bearer (each /install/resolve mints a new one)
    #   2. Installer writes new bearer to User-scope env var via
    #      SetEnvironmentVariable("...","User") — registry HKCU\Environment
    #   3. Operator restarts Claude Code, BUT new claude.exe inherits process
    #      env from whatever shell spawned it (Windows Terminal that was
    #      already open holds the STALE bearer from before the rotation)
    #   4. Claude Code's MCP client expands ${ALLOSTAT_MCP_TOKEN} against its
    #      stale process env → sends old bearer → 401 from server
    #   5. Banner shows "MCP failing to connect" forever
    #
    # The literal bearer here means Claude Code reads from disk every time,
    # zero dependence on env-var propagation. The plugin's .env backup +
    # this literal in .mcp.json + the literal in `claude mcp add` user-scope
    # registration all carry the same value. Env var still gets set as
    # convenience for shell users, but the regulator no longer depends on it.
    if ([string]::IsNullOrEmpty($Bearer)) {
        # Backward-compat fallback for callers that haven't been updated
        # to pass Bearer (e.g., repair-install.ps1 unchanged from v0.2.0).
        $authValue = "Bearer `${ALLOSTAT_MCP_TOKEN}"
    } else {
        $authValue = "Bearer $Bearer"
    }

    $mcpJsonContent = [pscustomobject]@{
        'allostat-mcp' = [pscustomobject]@{
            type    = "http"
            url     = "$ServerEndpoint/mcp"
            headers = [pscustomobject]@{
                'Authorization' = $authValue
                'Accept'        = "application/json, text/event-stream"
                'Content-Type'  = "application/json"
                'User-Agent'    = "allostat-mcp-wrapper/$Version (+https://allostat.ai)"
                # MCP-Protocol-Version intentionally OMITTED -- see PC-Claude Bug 2.
            }
        }
    }
    Write-ProtectedCredentialFile `
        -Path $McpJsonPath `
        -Content ($mcpJsonContent | ConvertTo-Json -Depth 10)
}

# ----------------------------------------------------------------------
# Repair-InstalledPluginsJson -- Fix "unknown" installPath / version.
#
# Claude Code's `claude plugin install` sometimes writes
# installPath: <cache>\<name>\unknown and version: "unknown" into
# ~/.claude/plugins/installed_plugins.json. The hook-discovery path
# rescues runtime loading in practice, but the registry record is wrong
# and a stricter loader version may not be forgiving.
#
# Idempotent: no-op if record is already correct.
# ----------------------------------------------------------------------

function Repair-InstalledPluginsJson {
    param(
        [Parameter(Mandatory=$true)] [string]$ClaudeDir,
        [Parameter(Mandatory=$true)] [string]$VersionCacheDir,
        [Parameter(Mandatory=$true)] [string]$Version,
        [string]$PluginKey = "allostat-mcp@local"
    )

    $ipPath = Join-Path $ClaudeDir "plugins\installed_plugins.json"
    if (-not (Test-Path $ipPath)) {
        return [pscustomobject]@{ ok = $true; changed = $false; reason = "installed_plugins.json absent" }
    }

    try {
        $ip = Get-Content -Path $ipPath -Raw | ConvertFrom-Json
    } catch {
        return [pscustomobject]@{ ok = $false; changed = $false; reason = "installed_plugins.json malformed: $($_.Exception.Message)" }
    }

    if (-not $ip.plugins.PSObject.Properties.Match($PluginKey).Count) {
        return [pscustomobject]@{ ok = $true; changed = $false; reason = "$PluginKey not present in installed_plugins.json" }
    }

    $entry = $ip.plugins.$PluginKey
    if (-not $entry) {
        return [pscustomobject]@{ ok = $true; changed = $false; reason = "$PluginKey entry empty" }
    }
    $firstRecord = $entry[0]

    # ultraswarm HIGH (install-shared.ps1:465): NEVER write a non-existent cache
    # dir or an 'unknown' placeholder as the authoritative installPath/version.
    # repair-install.ps1 can hand us a $VersionCacheDir pointing at a
    # non-existent ...\<version> path (cache layout differs) or ...\unknown
    # (plugin.json unreadable -> version='unknown'). Rewriting the registry to
    # that path breaks the loader and re-introduces the exact 'unknown'
    # corruption this function exists to repair. If the incoming target isn't a
    # real, resolved cache dir, leave installed_plugins.json untouched.
    if ($Version -eq 'unknown' -or $VersionCacheDir -match 'unknown' -or
        -not (Test-Path -LiteralPath $VersionCacheDir)) {
        return [pscustomobject]@{
            ok = $true
            changed = $false
            reason = "skipped: unresolved/invalid VersionCacheDir ('$VersionCacheDir') or version='$Version'; left installed_plugins.json unchanged"
        }
    }

    # PATCH-103 v0.1.10 bug fix: previously only "unknown" cases were
    # repaired. But `claude plugin install` returns success ("already
    # installed") on repeat installs without updating installPath/version
    # in the registry. Result: registry pointed at the OLD cache dir
    # (e.g., 0.1.5) even after new bundle extracted to cache/0.1.9/ —
    # Claude Code loaded hooks from the stale cache.
    #
    # Now rewrite whenever installPath OR version doesn't match what
    # this install is bringing on disk. This is the authoritative state
    # after a successful bundle extract.
    $needsRewrite = $false
    $reason = "record already correct"
    if ($firstRecord.installPath -match 'unknown' -or $firstRecord.version -eq 'unknown') {
        $needsRewrite = $true
        $reason = "corrected unknown placeholders"
    } elseif ($firstRecord.installPath -ne $VersionCacheDir) {
        $needsRewrite = $true
        $reason = "corrected stale installPath (was $($firstRecord.installPath), now $VersionCacheDir)"
    } elseif ($firstRecord.version -ne $Version) {
        $needsRewrite = $true
        $reason = "corrected stale version (was $($firstRecord.version), now $Version)"
    }

    if (-not $needsRewrite) {
        return [pscustomobject]@{ ok = $true; changed = $false; reason = $reason }
    }

    $nowIso = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $firstRecord.installPath = $VersionCacheDir
    $firstRecord.version = $Version
    $firstRecord.lastUpdated = $nowIso

    Write-Utf8NoBom -Path $ipPath -Content ($ip | ConvertTo-Json -Depth 10)
    return [pscustomobject]@{ ok = $true; changed = $true; reason = $reason }
}

# ----------------------------------------------------------------------
# Invoke-ClaudeMcpAdd -- Idempotent claude mcp add at user scope.
#
# Per PC-Claude brief + Surface Pro dogfood 2026-05-15:
#   1. `claude mcp remove --scope user` first (idempotent, clears stale bearer)
#   2. `claude mcp add --scope user --transport http <url> --header "Authorization: Bearer <bearer>"`
#   3. NO MCP-Protocol-Version header (CLI sets its own; duplicate breaks server)
#   4. NO Accept / Content-Type headers (CLI defaults handle them)
#   5. --scope user is critical -- default `local` writes to cwd's .claude.json
#
# Returns PSCustomObject with .ok + .output (stdout/stderr combined).
# ----------------------------------------------------------------------

function Invoke-ClaudeMcpAdd {
    param(
        [Parameter(Mandatory=$true)] [string]$ClaudeExe,
        [Parameter(Mandatory=$true)] [string]$ServerEndpoint,
        [Parameter(Mandatory=$true)] [string]$Bearer,
        [string]$ServerName = "allostat-mcp"
    )

    # v0.2.2 PATCH-122: use the call-operator (&) with try/catch wrapping.
    #
    # History:
    #   v0.2.0 used `& $ClaudeExe ... 2>&1 | Out-Null` which triggers
    #     NativeCommandError when claude.exe writes "No project-local MCP
    #     server found" to stderr. PS 5.1 wraps native stderr into
    #     ErrorRecord through the pipeline; $ErrorActionPreference = "Stop"
    #     then aborts the script before `claude mcp add` runs.
    #   v0.2.1 attempted Start-Process with -ArgumentList @(...) array form
    #     to bypass the pipeline. That fixed the NativeCommandError but
    #     broke argument passing: Start-Process joins array elements with
    #     a space, so "Authorization: Bearer xxx" got split on the space
    #     and claude.exe rejected with "Invalid header format: 'Bearer'".
    #   v0.2.2 (this) goes back to `&` (proven arg passing for headers
    #     with spaces) but wraps each native call in try/catch. The catch
    #     swallows NativeCommandError so the idempotent `mcp remove` calls
    #     don't abort the script when no entry exists. Verified locally:
    #     try/catch caught "No project-local MCP server found" and "No
    #     user-scoped MCP server found" cleanly, and the subsequent
    #     `mcp add` with --header succeeded.

    # Step 1: idempotent removes at both scopes. We expect these to often
    # produce stderr errors (no such entry) — wrap in try/catch so the
    # NativeCommandError doesn't abort the caller's script.
    try {
        & $ClaudeExe mcp remove $ServerName --scope local 2>&1 | Out-Null
    } catch {
        # Expected when no local-scope entry exists. Swallow.
    }
    try {
        & $ClaudeExe mcp remove $ServerName --scope user 2>&1 | Out-Null
    } catch {
        # Expected when no user-scope entry exists. Swallow.
    }

    # Step 2: the add. We do care about the result here. Catch the
    # NativeCommandError separately so we can return structured failure
    # detail (vs a script-level abort).
    $addOk = $false
    $addOutput = $null
    # NOTE (ultraswarm argv review): the bearer rides `mcp add --header` on the
    # child argv, briefly visible via Win32 process command line. This is
    # INHERENT to the Claude CLI — `claude mcp add` exposes only `--header` for
    # HTTP auth (no env/file/stdin option; confirmed via `claude mcp add --help`),
    # so it cannot be moved off argv from here. One-shot at install; not fixable
    # our side. Revisit if the CLI adds a non-argv header path.
    try {
        $addOutput = & $ClaudeExe mcp add $ServerName `
            --scope user `
            --transport http "$ServerEndpoint/mcp" `
            --header "Authorization: Bearer $Bearer" `
            2>&1
        $addOk = ($LASTEXITCODE -eq 0)
    } catch {
        # Even on stderr-only errors, $LASTEXITCODE reflects the real exit
        # code from claude.exe. Inspect both before declaring failure.
        $addOk = ($LASTEXITCODE -eq 0)
        if (-not $addOutput) {
            $addOutput = $_.Exception.Message
        }
    }

    return [pscustomobject]@{
        ok = $addOk
        output = if ($addOutput) { ($addOutput -join "`n") } else { "(no output captured)" }
    }
}


# ----------------------------------------------------------------------
# Get-RegisteredMcpBearer -- Read the user-scope MCP registration's bearer
# from ~/.claude.json. Returns the bearer string or $null.
#
# v0.2.1 PATCH-122 helper. Used by Confirm-McpRegistrationCurrent to
# detect when `claude mcp add` reported success but the registry stayed
# stale (the symptom that caused the "same problem every update" bug).
# ----------------------------------------------------------------------
function Get-RegisteredMcpBearer {
    param(
        [Parameter(Mandatory=$true)] [string]$ClaudeExe,
        [string]$ServerName = "allostat-mcp"
    )

    # F3 fix (2026-05-29): read the registered bearer via the CLI's OWN
    # `claude mcp get`, NOT by hand-parsing ~/.claude.json. Root cause of the
    # "bearer did NOT take after retry" failure on every upgrade: `claude mcp
    # add --scope user` stores the registration wherever the installed Claude
    # Code version keeps user-scope config — which is NOT always top-level
    # ~/.claude.json `mcpServers`. The old file-parser returned $null when the
    # layout differed, so Confirm-McpRegistrationCurrent declared "registration
    # write failed" even though the add SUCCEEDED (manual recovery used the
    # identical `claude mcp add` and worked; `claude mcp get` shows it Connected).
    # Validated on a live machine: CLI read matches the expected bearer where the
    # file parse returned null. The CLI read is layout-independent + authoritative.
    #
    # `claude mcp get <name>` output includes (indented under "Headers:"):
    #     Authorization: Bearer <token>
    $out = $null
    try {
        $out = & $ClaudeExe mcp get $ServerName 2>&1
    } catch {
        $out = $_.Exception.Message
    }
    if ($out) {
        foreach ($line in (($out -join "`n") -split "`n")) {
            if ($line -match 'Authorization:\s*Bearer\s+(\S+)') {
                return $matches[1].Trim()
            }
        }
    }

    # Fallback: legacy top-level ~/.claude.json mcpServers parse (older Claude
    # Code layouts, or if `claude mcp get` output format changes).
    $claudeConfig = Join-Path $env:USERPROFILE ".claude.json"
    if (-not (Test-Path $claudeConfig)) { return $null }
    try {
        $config = Get-Content -Path $claudeConfig -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        return $null
    }
    if ($config.PSObject.Properties.Match('mcpServers').Count -and
        $config.mcpServers.PSObject.Properties.Match($ServerName).Count) {
        $auth = $config.mcpServers.$ServerName.headers.Authorization
        if ($auth -and $auth -match '^Bearer\s+(.+)$') {
            return $matches[1].Trim()
        }
    }

    return $null
}


# ----------------------------------------------------------------------
# Confirm-McpRegistrationCurrent -- Verify ~/.claude.json's user-scope
# allostat-mcp bearer matches the expected (just-resolved) bearer. If
# not, force a remove + re-add cycle and re-verify.
#
# v0.2.1 PATCH-122. This is the self-healing step the v0.2.0 installer
# was missing. Even when Invoke-ClaudeMcpAdd reports success, on some
# Windows/Claude-CLI combos the registry write silently fails or the
# add lands at a different scope. This function makes the install
# self-correcting on every run — fresh install, upgrade, repair, all
# converge on "the bearer in ~/.claude.json equals the bearer the
# installer just got from /install/resolve."
#
# Returns PSCustomObject: { ok, actions = [...], final_bearer_prefix }.
# ----------------------------------------------------------------------
function Confirm-McpRegistrationCurrent {
    param(
        [Parameter(Mandatory=$true)] [string]$ClaudeExe,
        [Parameter(Mandatory=$true)] [string]$ServerEndpoint,
        [Parameter(Mandatory=$true)] [string]$Bearer,
        [string]$ServerName = "allostat-mcp"
    )

    $actions = @()

    $registeredBearer = Get-RegisteredMcpBearer -ClaudeExe $ClaudeExe -ServerName $ServerName
    if ($registeredBearer -eq $Bearer) {
        $actions += "registered bearer already matches resolved bearer"
        return [pscustomobject]@{
            ok = $true
            actions = $actions
            final_bearer_prefix = if ($Bearer.Length -ge 8) { $Bearer.Substring(0, 8) + "..." } else { $Bearer }
        }
    }

    # Mismatch (or missing). Force a fresh add cycle.
    if ([string]::IsNullOrEmpty($registeredBearer)) {
        $actions += "no user-scope MCP registration found — adding"
    } else {
        $regPrefix = if ($registeredBearer.Length -ge 8) { $registeredBearer.Substring(0, 8) } else { $registeredBearer }
        $expPrefix = if ($Bearer.Length -ge 8) { $Bearer.Substring(0, 8) } else { $Bearer }
        $actions += "registered bearer ($regPrefix...) != resolved bearer ($expPrefix...) — re-adding"
    }

    $addResult = Invoke-ClaudeMcpAdd `
        -ClaudeExe $ClaudeExe `
        -ServerEndpoint $ServerEndpoint `
        -Bearer $Bearer `
        -ServerName $ServerName
    $actions += "Invoke-ClaudeMcpAdd returned ok=$($addResult.ok)"

    # Re-verify after the add.
    $afterBearer = Get-RegisteredMcpBearer -ClaudeExe $ClaudeExe -ServerName $ServerName
    $finalOk = ($afterBearer -eq $Bearer)
    if ($finalOk) {
        $actions += "post-re-add bearer matches resolved bearer — registration current"
    } else {
        $actions += "post-re-add bearer STILL doesn't match — registration write failed"
    }

    return [pscustomobject]@{
        ok = $finalOk
        actions = $actions
        final_bearer_prefix = if ($afterBearer -and $afterBearer.Length -ge 8) { $afterBearer.Substring(0, 8) + "..." } else { $afterBearer }
    }
}

# ----------------------------------------------------------------------
# Test-McpToolsListProbe -- Layer 5: real authenticated MCP request.
#
# POSTs an MCP `initialize` request to /mcp with the bearer. Returns:
#   .ok       -- boolean, true if 200
#   .status   -- HTTP status code (int) or $null on connection error
#   .detail   -- error message or status text
#
# WHY initialize (not tools/list): The MCP Streamable HTTP transport
# requires a session-establishing `initialize` request as the FIRST call
# in a session. A raw `tools/list` without prior initialize returns
# 400 Bad Request (the SDK rejects it as malformed protocol). Verified
# 2026-05-16: bare tools/list gets 400, initialize gets 200 + capabilities.
#
# Layer 5 catches install-time degradation that the previous 4 layers
# miss: server registered AND connected per `claude mcp list` but actual
# protocol exchange fails (401 auth, 400 protocol, etc.).
# ----------------------------------------------------------------------

function Test-McpToolsListProbe {
    param(
        [Parameter(Mandatory=$true)] [string]$ServerEndpoint,
        [Parameter(Mandatory=$true)] [string]$Bearer,
        [int]$TimeoutSec = 10
    )

    # MCP initialize handshake -- the protocol's mandatory first request.
    $probeBody = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"allostat-installer-probe","version":"0.1.7"}}}'
    $probeHeaders = @{
        'Authorization' = "Bearer $Bearer"
        'Accept'        = 'application/json, text/event-stream'
        'Content-Type'  = 'application/json'
    }

    try {
        $response = Invoke-WebRequest `
            -Uri "$ServerEndpoint/mcp" `
            -Method Post `
            -Body $probeBody `
            -Headers $probeHeaders `
            -TimeoutSec $TimeoutSec `
            -UseBasicParsing
        return [pscustomobject]@{
            ok = ($response.StatusCode -eq 200)
            status = $response.StatusCode
            detail = "HTTP $($response.StatusCode)"
        }
    } catch [System.Net.WebException] {
        $statusCode = $null
        try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        return [pscustomobject]@{
            ok = $false
            status = $statusCode
            detail = $_.Exception.Message
        }
    } catch {
        return [pscustomobject]@{
            ok = $false
            status = $null
            detail = $_.Exception.Message
        }
    }
}

# ----------------------------------------------------------------------
# Invoke-FourLayerValidation -- composite check matching install_validation.py.
#
# Layers and precedence per advisor 2026-05-16 review §2.1:
#   1. Plugin loaded?       claude plugin list  →  Status: ✔ enabled
#   2. MCP registered?      claude mcp list      →  allostat-mcp present
#   3. Server reachable?    HEAD /healthz       →  any response
#   4. MCP connected?       claude mcp list      →  ✓ Connected
#   5. MCP callable (opt)?  POST /mcp tools/list →  200
#
# Returns PSCustomObject:
#   .state           -- one of: healthy, degraded_plugin_not_loaded,
#                      degraded_mcp_not_registered,
#                      degraded_mcp_failed_connect, unreachable_server
#   .ok              -- bool ($state -eq "healthy")
#   .fix_hint        -- operator-facing recovery instruction
#   .detail          -- hashtable of raw layer results for diagnostic
# ----------------------------------------------------------------------

$script:_DOCTOR_CMD_HINT = '& "$env:USERPROFILE\.claude\plugins\marketplaces\local\allostat-mcp\scripts\allostat-doctor.ps1"'

function Invoke-FourLayerValidation {
    param(
        [Parameter(Mandatory=$true)] [string]$ClaudeExe,
        [string]$ServerEndpoint = "https://mcp.allostat.ai",
        [string]$Bearer = $null,
        [switch]$SkipCallableProbe
    )

    $detail = [ordered]@{}

    # Force UTF-8 stdout encoding so claude.exe's UTF-8 output isn't
    # transcoded by PowerShell's default OEM/cp1252 to ASCII approximations
    # (e.g., ❯->>, ✔->√, ✘->×) which break the regex patterns below.
    # Tested 2026-05-16: without this, `& claude plugin list` captures
    # `> allostat-mcp@local` + `Status: √ enabled` instead of `❯` + `✔`.
    $prevOutputEncoding = [Console]::OutputEncoding
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8

    try {

    # Layer 1 -- plugin loaded?
    $pluginListOutput = & $ClaudeExe plugin list 2>&1
    $pluginListText = ($pluginListOutput -join "`n")
    $detail.plugin_list_output = $pluginListText

    $pluginLoaded = $null
    if ($LASTEXITCODE -eq 0) {
        $allMcpBlock = $false
        $inAllostatMcp = $false
        $enabled = $false
        $disabled = $false
        # Block-start marker is `❯` in UTF-8 capture or `>` if transcoded.
        # Status icons: ✔/√ for enabled, ✘/× for disabled. Match either form.
        foreach ($line in ($pluginListText -split "`n")) {
            if ($line -match '^\s*(?:❯|>)\s+allostat-mcp@local\b') {
                $inAllostatMcp = $true
                $allMcpBlock = $true
                continue
            }
            if ($line -match '^\s*(?:❯|>)\s+\S') {
                $inAllostatMcp = $false
                continue
            }
            if ($inAllostatMcp) {
                if ($line -match 'Status:\s*(?:✔|√)\s*enabled') { $enabled = $true }
                if ($line -match 'Status:\s*(?:✘|×|x)\s*disabled') { $disabled = $true }
            }
        }
        if (-not $allMcpBlock) { $pluginLoaded = $false }
        elseif ($enabled) { $pluginLoaded = $true }
        elseif ($disabled) { $pluginLoaded = $false }
        else { $pluginLoaded = $false }
    }
    $detail.plugin_loaded = $pluginLoaded

    # Layer 2/4 -- MCP registered + connection status?
    $mcpListOutput = & $ClaudeExe mcp list 2>&1
    $mcpListText = ($mcpListOutput -join "`n")
    $detail.mcp_list_output = $mcpListText

    $mcpStatus = $null  # "connected" / "failed" / "missing"
    if ($LASTEXITCODE -eq 0) {
        # Check Connected for allostat / allostat-mcp / plugin-namespaced. The CLI
        # emits HEAVY ✔ (U+2714) — NOT light ✓ (U+2713); match both weights + the
        # √ cp437 transcode. (2026-07-06: light-only match false-flagged DEGRADED.)
        if ($mcpListText -match '(?m)(?:^|\s)(?:allostat|allostat-mcp|plugin:allostat-mcp:allostat-mcp):[^\n]*?-\s*(?:✓|✔|√)\s*Connected' -or
            $mcpListText -match '(?m)mcp\.allostat\.ai[^\n]*?-\s*(?:✓|✔|√)\s*Connected') {
            $mcpStatus = "connected"
        } elseif ($mcpListText -match '(?m)(?:^|\s)(?:allostat|allostat-mcp|plugin:allostat-mcp:allostat-mcp):[^\n]*?-\s*(?:(?:✗|✘|×|x)\s*Failed|!\s*Needs)' -or
                  $mcpListText -match '(?m)mcp\.allostat\.ai[^\n]*?-\s*(?:(?:✗|✘|×|x)\s*Failed|!\s*Needs)') {
            $mcpStatus = "failed"
        } elseif ($mcpListText -match '(?m)(?:^|\s)(?:allostat|allostat-mcp)\b' -or
                  $mcpListText -match 'mcp\.allostat\.ai') {
            # Entry present but no clear status indicator -- conservative: failed
            $mcpStatus = "failed"
        } else {
            $mcpStatus = "missing"
        }
    }
    } finally {
        [Console]::OutputEncoding = $prevOutputEncoding
    }
    $detail.mcp_status = $mcpStatus

    # Layer 3 -- server reachable?
    $serverReachable = $false
    try {
        $netResponse = Invoke-WebRequest `
            -Uri "$ServerEndpoint/healthz" `
            -Method Head `
            -TimeoutSec 5 `
            -UseBasicParsing `
            -ErrorAction SilentlyContinue
        $serverReachable = ($netResponse -ne $null)
    } catch [System.Net.WebException] {
        # 4xx counts as reachable
        $statusCode = $null
        try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        $serverReachable = ($statusCode -ne $null)
    } catch {
        $serverReachable = $false
    }
    $detail.server_reachable = $serverReachable

    # Layer 5 -- MCP callable (optional)?
    $mcpCallable = $null
    if (-not $SkipCallableProbe -and $Bearer) {
        $probeResult = Test-McpToolsListProbe -ServerEndpoint $ServerEndpoint -Bearer $Bearer
        $detail.mcp_callable = $probeResult.ok
        $detail.mcp_callable_status = $probeResult.status
        $detail.mcp_callable_detail = $probeResult.detail
        $mcpCallable = $probeResult.ok
    }

    # Precedence per advisor §2.1
    if ($pluginLoaded -eq $false) {
        return [pscustomobject]@{
            state = "degraded_plugin_not_loaded"
            ok = $false
            fix_hint = "Plugin failed to load (Claude Code rejected its manifest). Re-run the installer from your install email, or run the health-check: $script:_DOCTOR_CMD_HINT"
            detail = $detail
        }
    }
    if ($mcpStatus -eq "missing") {
        return [pscustomobject]@{
            state = "degraded_mcp_not_registered"
            ok = $false
            fix_hint = "MCP server not registered with Claude Code. Re-run the installer, or run the health-check: $script:_DOCTOR_CMD_HINT"
            detail = $detail
        }
    }
    if (-not $serverReachable) {
        return [pscustomobject]@{
            state = "unreachable_server"
            ok = $false
            fix_hint = "Check your internet connection. If you're online, the Allostat server may be temporarily down -- try again in a few minutes."
            detail = $detail
        }
    }
    if ($mcpStatus -eq "failed" -or ($mcpCallable -eq $false)) {
        return [pscustomobject]@{
            state = "degraded_mcp_failed_connect"
            ok = $false
            fix_hint = "MCP server registered but failing to connect (bearer may be stale). Re-run the installer with a fresh install code to refresh credentials. Health-check: $script:_DOCTOR_CMD_HINT"
            detail = $detail
        }
    }

    return [pscustomobject]@{
        state = "healthy"
        ok = $true
        fix_hint = $null
        detail = $detail
    }
}

# ----------------------------------------------------------------------
# Format-StatusReport -- Pretty-print Invoke-FourLayerValidation result.
#
# Used by allostat-doctor.ps1 and by install.ps1 Step 12b INCOMPLETE
# message. -Verbose flag dumps raw CLI outputs in addition to summary.
# ----------------------------------------------------------------------

function Format-StatusReport {
    # NOTE: -Verbose is a PowerShell common parameter and CANNOT be used as
    # a custom param name (PS rejects with "parameter ... defined multiple
    # times"). Renamed to -ShowDetail. Callers must use -ShowDetail or
    # rely on the default (no detail dump).
    param(
        [Parameter(Mandatory=$true)] $Status,
        [switch]$ShowDetail
    )

    Write-Host ""
    Write-Host "================================================" -ForegroundColor $(if ($Status.ok) {"Green"} else {"Yellow"})
    if ($Status.ok) {
        Write-Host "  Allostat health: ✓ HEALTHY" -ForegroundColor Green
    } else {
        Write-Host "  Allostat health: ⚠ $($Status.state.ToUpper())" -ForegroundColor Yellow
    }
    Write-Host "================================================" -ForegroundColor $(if ($Status.ok) {"Green"} else {"Yellow"})
    Write-Host ""

    # Layer-by-layer summary
    Write-Host "Layer 1 (plugin loaded):     $(if ($Status.detail.plugin_loaded -eq $true) {'✓'} elseif ($Status.detail.plugin_loaded -eq $false) {'✗'} else {'?'})"
    Write-Host "Layer 2 (MCP registered):    $(if ($Status.detail.mcp_status -eq 'connected' -or $Status.detail.mcp_status -eq 'failed') {'✓'} elseif ($Status.detail.mcp_status -eq 'missing') {'✗'} else {'?'})"
    Write-Host "Layer 3 (server reachable):  $(if ($Status.detail.server_reachable) {'✓'} else {'✗'})"
    Write-Host "Layer 4 (MCP connected):     $(if ($Status.detail.mcp_status -eq 'connected') {'✓'} elseif ($Status.detail.mcp_status -eq 'failed') {'✗'} else {'?'})"
    if ($Status.detail.Contains('mcp_callable')) {
        Write-Host "Layer 5 (MCP callable):      $(if ($Status.detail.mcp_callable) {'✓'} else {'✗'})"
    }
    Write-Host ""

    if (-not $Status.ok -and $Status.fix_hint) {
        Write-Host "Fix:" -ForegroundColor Yellow
        Write-Host "  $($Status.fix_hint)"
        Write-Host ""
    }

    if ($ShowDetail) {
        Write-Host "---" -ForegroundColor DarkGray
        Write-Host "Raw diagnostic detail:" -ForegroundColor DarkGray
        $Status.detail | Format-List | Out-String | Write-Host
    }
}

# ----------------------------------------------------------------------
# Get-BearerFromEnvFile -- Read bearer from plugin's .env backup.
#
# install.ps1 writes the bearer to <WrapperDir>\.env as a backup so
# repair-install.ps1 and allostat-doctor.ps1 can recover it without
# requiring the user to re-mint an install code.
#
# Returns the bearer string, or $null if .env is missing/malformed.
# ----------------------------------------------------------------------

function Get-BearerFromEnvFile {
    param(
        [string]$WrapperDir = $null
    )
    if (-not $WrapperDir) { $WrapperDir = Get-PluginRoot }
    $envPath = Join-Path $WrapperDir ".env"
    if (-not (Test-Path $envPath)) { return $null }
    try {
        $content = Get-Content -Path $envPath -Raw
        if ($content -match 'ALLOSTAT_MCP_TOKEN=(\S+)') {
            return $matches[1].Trim()
        }
    } catch {
        return $null
    }
    return $null
}
