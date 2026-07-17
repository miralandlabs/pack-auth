# AGENTS.template.md

Optional verification kit for this repo and other projects. **Not active policy by itself**—follow [`AGENTS.md`](./AGENTS.md) first. Use a block below only after confirming that stack exists in the target repository.

Customize paths and package managers to match the project.

## Rust

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # warnings fail CI
cargo test --all-targets
```

## Node.js / TypeScript

```bash
# Run install if package.json or lockfile changed
npm install                          # Substitute with pnpm / yarn if applicable

# Run project checks (if defined in package.json)
npm run lint                         # Ensure warnings are zero
npm run typecheck                    # If not defined, run: npx tsc --noEmit
npm test                             # Run unit/integration tests
npm run build                        # Required when packages or SDKs change
```

## Python

```bash
ruff check .
black --check .
mypy .
pytest
```

## Go

```bash
go fmt ./...
go vet ./...
go test ./...
```

## Ruby

```bash
bundle exec rubocop
bundle exec rspec
```
