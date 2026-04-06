# Skill Index for backendTesis

This index maps the original Claude skills to project-local GitHub skills and context files.

## Source to local mapping

| Source skill (Claude) | Local target in this repo | Purpose |
| --- | --- | --- |
| phishing-detection | .github/skills/backend-pipeline/SKILL.md | End-to-end phishing pipeline guidance |
| idn-homograph-detection | .github/skills/backend-pipeline/SKILL.md | IDN analysis and scoring constraints |
| llamastack-patterns | .github/skills/backend-pipeline/SKILL.md | LLM integration and fallback behavior |
| huggingface-patterns | .github/skills/backend-pipeline/SKILL.md | Embeddings and vector context patterns |
| backend-patterns | .github/skills/backend-pipeline/SKILL.md | API route orchestration and service boundaries |
| python-patterns | .github/instructions/python-fastapi.instructions.md | Python quality and async rules |
| python-testing | .github/instructions/tests.instructions.md | Unit and integration test strategy |
| tdd-workflow | .github/context/execution-steps.md | Test-first workflow and checkpoints |
| security-review | .github/rules/SECURITY_TESTING_RULES.md | Security baseline and pre-merge checks |

## Mandatory memory skill

- .github/skills/project-memory/SKILL.md is the default skill for keeping:
  - .github/context/work-log.md
  - .github/context/project-history.md
  - .github/context/next-steps.md

Use this memory skill in every non-trivial development session.
