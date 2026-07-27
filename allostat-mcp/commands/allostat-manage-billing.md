---
name: allostat-manage-billing
description: Open the authenticated Allostat billing portal to manage or cancel your subscription.
---

# /allostat-manage-billing

Open the customer billing portal using the credential already installed with
Allostat. The helper sends that credential only in an in-process Authorization
header. Never ask the operator to paste a token, and never put a token or portal
URL in arguments, shell text, or chat output.

Run exactly one block matching the operator's shell. Do not reference
`${CLAUDE_PLUGIN_ROOT}` or `$ALLOSTAT_PLUGIN_DIR`: command markdown does not
reliably expand those values. Both blocks discover all installed marketplaces,
keep only numeric Allostat version directories, and invoke the highest semantic
version that actually contains the helper.

## Windows PowerShell

<!-- b06:manage-billing-powershell:start -->
```powershell
$pluginsRoot = Join-Path $HOME ".claude\plugins"
$versionDirs = Get-ChildItem -Path $pluginsRoot -Recurse -File -Filter "manage_billing.py" -ErrorAction SilentlyContinue |
    Where-Object { $_.Directory.Name -eq "lib" } |
    ForEach-Object { $_.Directory.Parent } |
    Where-Object { $_.Parent.Name -eq "allostat-mcp" -and $_.Name -match '^\d+(\.\d+)*$' }
$root = $versionDirs | Sort-Object -Property @{Expression = { [version]$_.Name }} -Descending | Select-Object -First 1
if (-not $root) { throw "allostat-mcp plugin (with manage_billing.py) not found under $pluginsRoot" }
$pythonCommand = $null
$runtimeCandidates = @()
foreach ($name in @("python", "python3", "py")) {
    $runtimeCandidates += @(Get-Command $name -All -ErrorAction SilentlyContinue)
}
foreach ($resolved in $runtimeCandidates) {
    if (-not $resolved.Source -or $resolved.Source -match 'WindowsApps') { continue }
    & $resolved.Source -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >$null 2>&1
    if ($LASTEXITCODE -eq 0) { $pythonCommand = $resolved; break }
}
if (-not $pythonCommand) { throw "Python 3.11 or newer not found; Allostat billing was not opened" }
& $pythonCommand.Source (Join-Path $root.FullName "lib\manage_billing.py")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```
<!-- b06:manage-billing-powershell:end -->

## macOS or Linux POSIX shell

<!-- b06:manage-billing-posix:start -->
```bash
plugins_root="$HOME/.claude/plugins"
python_cmd=""
for candidate in python python3; do
  resolved="$(command -v "$candidate" 2>/dev/null || true)"
  if [ -n "$resolved" ] && "$resolved" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
    python_cmd="$resolved"
    break
  fi
done
if [ -z "$python_cmd" ]; then
  echo "Python 3.11 or newer not found; Allostat billing was not opened" >&2
  exit 1
fi
root="$("$python_cmd" - "$plugins_root" <<'PY'
import re
import sys
from pathlib import Path

candidates = []
for helper in Path(sys.argv[1]).rglob("manage_billing.py"):
    if helper.parent.name != "lib":
        continue
    version_dir = helper.parent.parent
    if version_dir.parent.name != "allostat-mcp":
        continue
    if not re.fullmatch(r"\d+(?:\.\d+)*", version_dir.name):
        continue
    candidates.append((tuple(int(part) for part in version_dir.name.split(".")), version_dir))
if candidates:
    print(max(candidates, key=lambda item: item[0])[1])
PY
)"
if [ -z "$root" ]; then
  echo "allostat-mcp plugin (with manage_billing.py) not found under $plugins_root" >&2
  exit 1
fi
"$python_cmd" "$root/lib/manage_billing.py"
```
<!-- b06:manage-billing-posix:end -->

On success, tell the operator only that the secure billing portal opened. On
failure, relay the helper's short message without adding request details. Do not
display or navigate to the returned portal URL manually.
