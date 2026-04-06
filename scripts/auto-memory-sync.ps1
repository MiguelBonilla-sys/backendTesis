Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonScript = Join-Path $scriptDir "auto_memory_sync.py"

if (-not (Test-Path $pythonScript)) {
    throw "auto-memory: missing script $pythonScript"
}

if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 $pythonScript
    exit $LASTEXITCODE
}

if (Get-Command python3 -ErrorAction SilentlyContinue) {
    & python3 $pythonScript
    exit $LASTEXITCODE
}

if (Get-Command python -ErrorAction SilentlyContinue) {
    & python $pythonScript
    exit $LASTEXITCODE
}

throw "auto-memory: no Python interpreter found (py/python3/python)"
