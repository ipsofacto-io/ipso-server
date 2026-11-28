# Agent instructions for `ipso-server`

## Local LLM evals

Live recordings for the `local` eval route (`Qwen3-4B-Q4_K_M`) run on developer hardware through `scripts/evals-local.sh` rather than on GitHub Actions (`ADR-0173`). `ci / test` replays `internal/evals/testdata/cassette.json` on every pull request, and `evals-provider.yml` runs the production route (`mistral-medium-latest`) on `main`.

- When a change modifies `internal/proposals/**`, `internal/llmgw/**`, or `internal/evals/**`, run `./scripts/evals-local.sh` once before committing or opening a pull request. Do not run it after every intermediate edit.
- Use default mode (`./scripts/evals-local.sh`) to verify that live scores hold against the committed baseline and floors without modifying `internal/evals/testdata/cassette.json`.
- Use `./scripts/evals-local.sh --record` only when a prompt changed and `go test ./...` fails with `ErrNotRecorded`, then review the diff of `internal/evals/testdata/cassette.json` before committing.
- Never run `./scripts/evals-local.sh --update` automatically to hide a score drop or lower a floor. Updating `baseline.json` or `docs/evals.md` requires explicit human review of the score diff.
- Fail closed on missing local prerequisites: if `llama-server` is not in `PATH` or `127.0.0.1:8080` is already in use, stop and report explicitly that live local evals did not run. Never skip the check silently or work around the gate.
