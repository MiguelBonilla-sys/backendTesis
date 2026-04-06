# Execution Steps

Use this flow for non-trivial changes.

## Step 1: Scope and context

- Read .github/context/project-context.md.
- Read docs/PLAN.md and relevant phase doc.
- Validate current runtime behavior in code before assuming doc status.

## Step 2: Plan

- Define expected behavior and acceptance checks.
- List impacted files and dependencies.
- Identify security and data-privacy implications.

## Step 3: Test-first

- Add or adjust tests for behavior change.
- Run targeted tests to confirm baseline/failure before fix when applicable.

## Step 4: Implement minimal diff

- Keep contracts stable unless explicitly changed.
- Keep async and stateless architecture.
- Keep cache-first TI path.

## Step 5: Validate

- Run unit tests for touched modules.
- Run integration tests if API/data-flow behavior changed.
- Run lint/security checks.

## Step 6: Review

- Run code review and security review.
- Resolve high severity findings first.

## Step 7: Memory update

- Append execution summary in .github/context/work-log.md.
- Update .github/context/next-steps.md.
- Update .github/context/project-history.md only if milestone/phase status changed.
