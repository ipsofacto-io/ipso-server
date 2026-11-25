# LLM evals

`internal/evals` scores each LLM pipeline on synthetic golden datasets and holds the score against a committed baseline ([ADR-0082](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0082-go-eval-harness.md), [ADR-0164](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0164-one-case-eval-gate-and-deterministic-eval-markers.md), [ADR-0165](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0165-eval-scores-on-the-production-route.md)). The datasets are the three suites of `internal/evals/testdata`: `pr` (decision extraction from a pull request discussion), `redteam` (prompt injection) and `checks` (drafted agent-edit checks). Every dataset is synthetic, and `TestDatasetsAreSynthetic` fails when one names a host or a mailbox domain that is not reserved (`.example`, `.test`, `.invalid`, `example.com`).

## Two routes

A recorded answer is keyed by its prompt and not by the model, so each route keeps its own answers and baseline, selected with `-route`.

| Route | Model | Where it runs | Files in `internal/evals/testdata` | Gated by |
| --- | --- | --- | --- | --- |
| `local` | Qwen3-4B Q4_K_M, served by llama.cpp on the runner | the `evals` workflow, and `go test ./...` in `ci / test` for the replay | `cassette.json`, `baseline.json`, `history.jsonl`, `local-model.json` | every pull request that touches the pipelines |
| `mistral` | the operator default route of the gateway, `mistral-medium-latest` | the `evals-provider` workflow, on `main` only | `mistral/cassette.json`, `mistral/baseline.json`, `mistral/history.jsonl`, `mistral/gateway.json` | the weekly run and a manual dispatch |

A pull request never calls a provider and never sees its key. `ci / test` replays the `local` route only. The `mistral` route is recorded by `evals-provider`, which reads the secret `IPSO_LLM_MISTRAL` of the GitHub environment `evals-provider`, an environment that only `main` may deploy to. A run that records is gated against the baseline of its own route: a metric more than one case below it fails, and so does a metric under its floor. A floor is the product target of section 9.9 of the spec, so both routes hold the same one.

## Scores

The baseline score of each metric, from the committed baselines. This table is generated: `go test ./internal/evals -run '^TestEvals$' -route <route> -update` rewrites it, and `TestScoresTable` fails when it is stale.

<!-- scores:start -->
| Metric | Floor | local (qwen3-4b-q4_k_m) | mistral (not recorded) |
| --- | --- | --- | --- |
| `checks.drafted` | 0.9 | 0.9 | not recorded |
| `checks.first` | none | 0.8 | not recorded |
| `checks.holdout` | none | 0.55 | not recorded |
| `pr.extract.precision` | 0.8 | 0.963 | not recorded |
| `pr.extract.recall` | 0.6 | 0.9286 | not recorded |
| `pr.extract.valid` | 0.9 | 1 | not recorded |
| `pr.screen.precision` | none | 0.8235 | not recorded |
| `pr.screen.recall` | none | 1 | not recorded |
| `redteam.canary.kept` | none | 1 | not recorded |
| `redteam.model.resisted` | none | 0.8182 | not recorded |
| `redteam.screen.detection` | none | 0.4054 | not recorded |
| `redteam.screen.specificity` | none | 0.5 | not recorded |
<!-- scores:end -->

## Record a route

For the `local` route, run the `evals` workflow, copy `cassette.json` from its artifact into `internal/evals/testdata`, and write the baseline:

```sh
go test ./internal/evals -run '^TestEvals$' -route local -update
```

For the `mistral` route, dispatch `evals-provider` on `main`, copy `cassette.json` from its artifact into `internal/evals/testdata/mistral`, and write the baseline:

```sh
go test ./internal/evals -run '^TestEvals$' -route mistral -update
```

`-update` keeps the floors, appends a line to the history of the route and rewrites the table above. Do not lower a floor or a baseline to make a run pass.

## Acceptance rate of proposals

The other half of the product measure is what reviewers answer. `ipso-server proposals acceptance --tenant <id>` reads it for one tenant, as the application role under row-level security, and prints a JSON report with a row for each kind of proposal, prompt version and model: the proposals approved, rejected and still pending, and the share approved of those answered. The target is 70% (section 1.6 of the spec). A row with fewer than 10 answered proposals reports no rate, because a handful of answers is not a share. Its counts are still printed. A check a person wrote is left out, because it is approved when it is stored. The report holds counts only and never names a person or groups by one ([ADR-0012](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0012-no-per-person-metrics.md), [ADR-0152](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0152-ai-act-guardrails.md)).
