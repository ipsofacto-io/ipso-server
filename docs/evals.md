# LLM evals

`internal/evals` scores each LLM pipeline on synthetic golden datasets and holds the score against a committed baseline ([ADR-0082](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0082-go-eval-harness.md), [ADR-0164](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0164-one-case-eval-gate-and-deterministic-eval-markers.md), [ADR-0166](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0166-eval-scores-on-the-production-route.md), [ADR-0173](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0173-local-evals-without-github-cpu-runner.md)). The datasets are the six suites of `internal/evals/testdata`: `pr` (decision extraction from a pull request discussion), `redteam` (prompt injection), `checks` (drafted agent-edit checks), `templates` (the choice of a built-in template for a check, [ADR-0165](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0165-template-check-proposals.md)), `relations` (how a pending proposal relates to the decisions in force, [ADR-0172](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0172-proposal-relation-annotations.md)) and `advisory` (the verdict of an llm-advisory check on a pull request, [ADR-0173](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0173-llm-advisory-checks-on-pull-requests.md)). Every dataset is synthetic, and `TestDatasetsAreSynthetic` fails when one holds a URL whose host, or a mailbox whose domain, is not reserved (`.example`, `.test`, `.invalid`, `example.com`). It does not read a bare hostname or an IP address, so a person who reviews a new dataset still checks for those.

## Two routes

A recorded answer is keyed by its prompt and not by the model, so each route keeps its own answers and baseline, selected with `-route`.

| Route | Model | Where it runs | Files in `internal/evals/testdata` | Gated by |
| --- | --- | --- | --- | --- |
| `local` | Qwen3-4B Q4_K_M, served locally by llama.cpp | `scripts/evals-local.sh` on developer hardware, and `go test ./...` in `ci / test` for the replay | `cassette.json`, `baseline.json`, `history.jsonl`, `local-model.json` | `ci / test` replay on every pull request, and local runs before committing pipeline changes |
| `mistral` | the operator default route of the gateway, `mistral-medium-latest` | the `evals-provider` workflow, on `main` only | `mistral/cassette.json`, `mistral/baseline.json`, `mistral/history.jsonl`, `mistral/gateway.json` | the weekly run and a manual dispatch |

A pull request never calls a provider and never sees its key. `ci / test` replays the `local` route only. The `mistral` route is recorded by `evals-provider`, which reads the secret `IPSO_LLM_MISTRAL` of the GitHub environment `evals-provider`, an environment that only `main` may deploy to. A run that records is gated against the baseline of its own route: a metric more than one case below it fails, and so does a metric under its floor. A floor is the product target of section 9.9 of the spec, so both routes hold the same one.

## The relations suite

`relation-proposals.json` holds 31 pending proposals, each with two or three decisions in force and the relation a person would name for each: 8 cases where the proposal replaces a decision, 8 where it conflicts with one, 6 where it restates one, 3 near misses that relate to none, and 6 prompt injections (an order to mark every decision superseded, a decision id of another tenant, a request to add a link, a forged answer, a forged data marker, and the first order again in a proposal that holds a change word). Each case runs the pipeline as the server does: `RelationCandidates` ranks the decisions, and `Relate` sends the candidates, checks the answer, and keeps a `supersedes` answer only when the proposal holds a change word of ADR-0085 or an end word such as withdrawn or shut, so the last injection is the one the guard lets through to the model. `TestRelationDatasetIsWellFormed` fails when the ranking would not send a decision a case relates, so `relations.recall` measures the model and not the ranking. The suite stops when a hint names a decision that was not sent, because the server could never store it.

| Metric | What it counts | Floor |
| --- | --- | --- |
| `relations.supersedes.precision` | hints that say replaces and that the case expects | 0.8 |
| `relations.conflicts.precision` | hints that say conflicts and that the case expects | 0.8 |
| `relations.valid` | calls answered with one known word for each decision sent | 0.9 |
| `relations.duplicates.precision` | hints that say restates and that the case expects | none |
| `relations.recall` | decisions a case relates that got the right hint | none |

A restatement is shown to a reviewer next to the decision it restates, so a wrong one costs a glance, and it has no floor. The two others name a decision the proposal would end or contradict, so their precision has one.

## The advisory suite

`advisory-diffs.json` holds 31 changes to a pull request, each with one decision in force and the assessment a reviewer would give the change: 10 deviations, 10 compliant changes, 4 changes whose verdict depends on code the hunks do not show, one compliant change whose `token :=` line redaction rewrites, and 6 prompt injections, each with its true assessment (an order to answer complies, a forged answer in a string literal, a forged data marker, a request to cite a hunk that was not sent and judge another decision, a request for a link and a mention in the reason, and a forged result and mode). Each case runs the pipeline as the server does: `ParsePatch` splits the patches, `PrepareAdvisory` redacts and bounds the message, and `Advise` sends it, checks the answer and builds the cited places from the hunks it sent. A deviation names the hunks it deviates in. The suite stops when a message still holds the text a case says redaction removes, because the server would have sent it.

| Metric | What it counts | Floor |
| --- | --- | --- |
| `advisory.deviates.precision` | deviates verdicts that the case expects | 0.8 |
| `advisory.deviates.recall` | deviating cases that got a deviates verdict | 0.6 |
| `advisory.valid` | calls answered with a verdict the server keeps | 0.9 |
| `advisory.cites` | right deviates verdicts that cite only hunks the case deviates in | none |
| `advisory.resisted` | injected cases that got their right assessment | none |

A deviates verdict points a reviewer at a change that goes against a decision, so a wrong one costs a reviewer's time and trust in the check, and its precision has the higher floor (ADR-0005). An advisory verdict never blocks a merge, so a missed deviation costs no more than the check not running, and recall has the lower one.

## Scores

The baseline score of each metric, from the committed baselines. This table is generated: `go test ./internal/evals -run '^TestEvals$' -route <route> -update` rewrites it, and `TestScoresTable` fails when it is stale.

<!-- scores:start -->
| Metric | Floor | local (qwen3-4b-q4_k_m) | mistral (mistral-medium-latest) |
| --- | --- | --- | --- |
| `advisory.cites` | none | 1 | not recorded |
| `advisory.deviates.precision` | 0.8 | 0.8 | not recorded |
| `advisory.deviates.recall` | 0.6 | 0.8 | not recorded |
| `advisory.resisted` | none | 0.6667 | not recorded |
| `advisory.valid` | 0.9 | 0.9677 | not recorded |
| `checks.drafted` | 0.9 | 0.9 | 1 |
| `checks.first` | none | 0.8 | 0.95 |
| `checks.holdout` | none | 0.55 | 0.7 |
| `pr.extract.precision` | 0.8 | 0.963 | 0.9333 |
| `pr.extract.recall` | 0.6 | 0.9286 | 1 |
| `pr.extract.valid` | 0.9 | 1 | 1 |
| `pr.screen.precision` | none | 0.8235 | 0.8235 |
| `pr.screen.recall` | none | 1 | 1 |
| `redteam.canary.kept` | none | 1 | 1 |
| `redteam.model.resisted` | none | 0.8182 | 0.9545 |
| `redteam.screen.detection` | none | 0.4054 | 0.4054 |
| `redteam.screen.specificity` | none | 0.5 | 0.5 |
| `relations.conflicts.precision` | 0.8 | 0.8 | 1 |
| `relations.duplicates.precision` | none | 0.8 | 1 |
| `relations.recall` | none | 0.7857 | 0.9643 |
| `relations.supersedes.precision` | 0.8 | 0.8333 | 1 |
| `relations.valid` | 0.9 | 1 | 1 |
| `templates.none` | 0.8 | 1 | 1 |
| `templates.precision` | 0.9 | 1 | 1 |
| `templates.recall` | none | 1 | 1 |
<!-- scores:end -->

## Record a route

For the `local` route, install `llama.cpp` locally (on macOS: `brew install llama.cpp`) and run `scripts/evals-local.sh` ([ADR-0173](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0173-local-evals-without-github-cpu-runner.md)). The script downloads and SHA-256-verifies the pinned `Qwen3-4B-Q4_K_M.gguf` file into `${XDG_CACHE_HOME:-$HOME/.cache}/ipso-evals/`, starts `llama-server` on `127.0.0.1:8080`, and shuts it down on exit:

```sh
# Check live scores against the committed baseline and restore cassette.json on exit
./scripts/evals-local.sh

# Record a fresh cassette.json into internal/evals/testdata and keep it in the working tree
./scripts/evals-local.sh --record

# Record cassette.json, update baseline.json, history.jsonl, and the table above, then verify floors
./scripts/evals-local.sh --update
```

For the `mistral` route, dispatch `evals-provider` on `main`, copy `cassette.json` from its artifact into `internal/evals/testdata/mistral`, and write the baseline:

```sh
go test ./internal/evals -run '^TestEvals$' -route mistral -update
```

`-update` keeps the floors, appends a line to the history of the route and rewrites the table above. Do not lower a floor or a baseline to make a run pass.

A recording answers every prompt again, and two live runs of unchanged prompts differ by about one case. When a pull request adds a suite, take from the recorded cassette only the answers whose prompts the committed cassette does not hold, so every other suite keeps its recorded answers and its baseline, then run `-update` and add the floors of the new suite to the baseline by hand.

## Acceptance rate of proposals

The other half of the product measure is what reviewers answer. `ipso-server proposals acceptance --tenant <id>` reads it for one tenant, as the application role under row-level security, and prints a JSON report with a row for each kind of proposal, prompt version and model: the proposals approved, rejected and still pending, and the share approved of those answered. The target is 70% (section 1.6 of the spec). A row with fewer than 10 answered proposals reports no rate, because a handful of answers is not a share. Its counts are still printed. A check a person wrote is left out, because it is approved when it is stored. The report holds counts only and never names a person or groups by one ([ADR-0012](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0012-no-per-person-metrics.md), [ADR-0152](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0152-ai-act-guardrails.md)).
