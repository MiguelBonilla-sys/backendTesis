Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
Set-Location $repoRoot

# 1) Sync auto-memory dirty-files snapshot
$syncScript = Join-Path $repoRoot "scripts/auto-memory-sync.ps1"
if (Test-Path $syncScript) {
    & $syncScript
}

# 2) Open reading order: context -> rules -> skills -> agents -> memory
$readingOrder = @(
    ".github/context/project-context.md",
    ".github/context/execution-steps.md",
    ".github/rules/PROJECT_RULES.md",
    ".github/rules/SECURITY_TESTING_RULES.md",
    ".github/skills/SKILL_INDEX.md",
    ".github/skills/backend-pipeline/SKILL.md",
    ".github/skills/project-memory/SKILL.md",
    ".github/agents/AGENTS.md",
    ".github/context/work-log.md",
    ".github/context/next-steps.md",
    ".github/auto-memory/config.json",
    ".github/auto-memory/dirty-files",
    ".github/context/TEAM_OPERATIVE_ONE_PAGER.md"
)

$existing = $readingOrder | Where-Object { Test-Path $_ }

if (Get-Command code -ErrorAction SilentlyContinue) {
    code -r $existing
    Write-Host "Daily workflow opened in VS Code." -ForegroundColor Green
} else {
    Write-Host "VS Code CLI (code) not found. Files to open manually:" -ForegroundColor Yellow
    $existing | ForEach-Object { Write-Host " - $_" }
}
