# AGENTS.md

Machine-readable contract for AI agents working in this repository. Follow it strictly.

## Repo

Miraland developer guide. Audience: developers building on or integrating with Miraland.

This tree is docs-first. Detect the real stack from manifests in the changed package root before assuming tooling. Do not invent project structure, pages, or commands that are not present.

## Non-negotiables

- **NEVER** commit, amend, or push unless the user explicitly asks.
- **NEVER** create, edit, or expand markdown/docs unless the task is documentation or the user explicitly asks.
- **NEVER** commit secrets (`.env`, API keys, tokens, credentials). Warn if asked to.
- **MUST** keep diffs surgical: every changed line traces to the assigned task. No drive-by refactors, formatting sweeps, or unsolicited cleanups.
- **MUST** reuse existing names, types, patterns, and tooling so changes read as if written by the original author.
- **MUST** ask when the goal is ambiguous or a choice needs user input only they can provide. After that, proceed; pause only for destructive actions, real scope changes, or that user-only input.
- **MUST** be decisive: when information is enough to act, act. Do not re-derive what is already established. When weighing options, give a recommendation with brief rationale—not an open-ended menu.
- **MUST** report only what this session can evidence. Audit claims against actual results; if something failed or is unverified, say so explicitly.
- **MUST NOT** add dependencies unless strictly necessary; prefer what already exists.

## Workflow

1. **Read** the target file, callers/imports, and nearby tests (or sibling docs) before editing.
2. **Change** only what the task requires. Prefer the smallest correct fix. Do not design for hypothetical future requirements.
3. **Match** local style and structure; do not introduce a parallel convention.
4. **Verify** with the protocol below. Read errors yourself—do not ask the user to run checks you can run.
5. **Report** leading with the outcome (first sentence answers “what happened”), then what changed, what you ran, and any blockers or open questions.

Philosophy in one line: **Simple, Concise, Clear, Clean (SCCC)** — smallest change that solves the task; no speculative features or abstractions.

## Verification

Always run from the package or workspace root that contains the modified code.

1. Inspect manifests first (`package.json`, `Cargo.toml`, `pyproject.toml`, `go.mod`, `Makefile`, etc.).
2. Prefer project-defined scripts (`lint`, `typecheck`, `test`, `build`, `fmt`, `check`).
3. Run only checks relevant to what changed.
4. If no verify command exists, say so and use the strongest local check available (e.g. link/path sanity for docs-only edits).
5. Never claim done without listing commands run—or why they could not run. Do not present unverified work as complete.

### Docs (this repo)

This tree is docs-first. Until project docs tooling lands (build, link check, lint), verify by path/link sanity against existing files and say so in the report. When docs tooling is added, document the commands here.

### When a stack is present

Use the matching block in [`AGENTS.template.md`](./AGENTS.template.md) only after confirming that stack exists in this repo. Do not run Rust/Node/Python/Go/Ruby commands by default.

### TypeScript (when applicable)

Command source of truth: the **Node.js / TypeScript** block in [`AGENTS.template.md`](./AGENTS.template.md) (install → lint → typecheck/`tsc --noEmit` → test → build), run only when that stack is present.

- Fix type errors at the source; avoid `any`, `@ts-ignore`, and unnecessary `as` casts unless surrounding code already relies on them.
- In monorepos, verify each affected workspace package.
- If only tests change and there is no general `test` script, run the project's specific test command.

## Done when

- [ ] Only task-related files touched
- [ ] Style and naming match the surrounding code/docs
- [ ] Verification ran (commands listed) or inability to run is explained
- [ ] Claims in the report match evidence from this session; failures/unverified work called out
- [ ] No secrets; no unsolicited docs/commits/pushes
- [ ] Ambiguities and tradeoffs surfaced to the user when relevant

## Ask first when

- The goal itself is ambiguous (ask before starting)
- Adding, renaming, or deleting docs pages or top-level structure
- Introducing a new dependency, tool, or CI workflow
- Incompatible API, naming, or architecture options where the user must decide
- Expanding scope beyond the user’s request, or any destructive action
- Anything that would require inventing content, paths, or commands not evidenced in the repo

Otherwise keep going. Prefer one recommended path over a menu of options the user did not ask to choose among.

## Out of scope unless asked

- Scaffolding apps, SDKs, or sample projects
- Broad refactors or “while I’m here” cleanups
- New CI, release, or packaging pipelines
- Copying multi-language verification kits into this file (keep those in `AGENTS.template.md`)
