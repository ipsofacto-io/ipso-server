# Verdict uploads

A CI job uploads the verdicts of an `ipso check` run, and the control plane stores them under the tenant that owns the repository, so a person sees check results per repository and decision. The contract is [ADR-0102](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0102-signed-verdict-uploads.md) in `ipsofacto-io/ipso-spec`. The route is `POST /v1/verdicts` and the read is `GET /v1/verdicts`, both described in [api/openapi.yaml](../api/openapi.yaml).

## What is uploaded and what is not

The body is the verdict report that `ipso check <command> --report <file>` writes ([ADR-0030](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0030-verdict-report-contract.md)), the name of the command, and optionally the SHA-256 of the SARIF file the same command wrote with `--sarif`. The report holds hashes, counts and the result of each decision check. It holds no plan value, no resource address and no violation message, and the SARIF file itself is never sent, so no source code or plan leaves the runner ([ADR-0006](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0006-local-first-evaluation.md)).

A version 2 report also holds, for each decision check, the sorted digests of its violations ([ADR-0122](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0122-baseline-on-verdict-reads.md)). A digest is the HMAC-SHA-256 that `ipso baseline` computes under the salt that stays in the repository ([ADR-0059](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0059-baseline-fingerprint-contract.md)), so the server holds digests and never a path, an address or a message. A check that a waiver covers, that failed to evaluate, that has no baseline on the runner, or that has a violation with no identity sends none. The server accepts reports of version 1 and 2, and refuses a list that is not sorted, repeats a digest, is on a pass or an error, or is shorter than the violations it counts.

```json
{"check": "plan", "report": { "...": "the report file as written" }, "sarif_sha256": "<64 lowercase hex>"}
```

The body has no field for a tenant, a repository, a commit or a run. They come from the signed token of the job. A body with any field the contract does not list is refused with 400, and so is a report whose keys are not exactly those of its command.

## Who may upload

An upload is accepted only with a GitHub Actions OIDC token, sent as `Authorization: Bearer`, for the audience you configure. The server asks GitHub, as the GitHub App, which installation covers the repository the token names, checks that the installation is on the account that owns the repository, and reads the tenant from `tenancy.installation` ([ADR-0101](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0101-installation-tenant-mapping.md)). A repository that no installation of this server's tenant covers gets 403 and stores nothing. So the installation has to be [bound to the tenant](github-app.md#bind-an-installation-to-its-tenant) first.

Any workflow of a covered repository can upload, because the server trusts the verdicts it is sent. Each row records the `workflow_ref` of the job, so a reader sees which workflow produced it.

## Turn it on

Uploads are off until `IPSO_CI_AUDIENCE` is set on `ipso-server --role=api`, and then the App ID and key are required too. The App settings alone change nothing, so an environment shared with `webhooks` is safe. The process refuses to start when the audience equals the API audience or the remote MCP resource, when it cannot read the GitHub Actions issuer over https, or when the App does not have exactly the permissions of section 3.1.

| Variable | Meaning |
| --- | --- |
| `IPSO_CI_AUDIENCE` | Turns uploads on. The audience the OIDC tokens of CI jobs must name. Any string that is not the API audience, such as `https://ipso.example.com/ci` |
| `IPSO_GITHUB_APP_ID` | Required with the audience. The numeric App ID, as for `webhooks` |
| `IPSO_GITHUB_APP_PRIVATE_KEY` | Required with the audience. The private key as PEM, as for `webhooks` |

The API process now holds the App key, which can mint installation tokens. The code uses it to read the App at start and to ask which installation covers a repository, and to nothing else. The Compose stack leaves uploads off.

## Upload from a workflow

The simplest way is [`ipso-action`](https://github.com/ipsofacto-io/ipso-action), which uploads the report of each check when you set `server-url` and `server-audience` ([ADR-0105](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0105-action-verdict-upload.md)). The audience is the value of `IPSO_CI_AUDIENCE`, and the job needs `id-token: write` in addition to its other permissions. The action uploads after a failed check too, and a failed upload only prints a warning, so the result of the step stays the result of the check. It hands out the `upload-id` of the answer as an output.

```yaml
permissions:
  contents: read
  id-token: write
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - uses: ipsofacto-io/ipso-action@<sha>
        with:
          command: plan
          args: plan.json
          env: prod
          server-url: https://ipso.example.com
          server-audience: https://ipso.example.com/ci
```

Without the action, a job needs `id-token: write` to request a token. Run the upload with `if: always()`, so that a failed check is stored too.

```yaml
permissions:
  contents: read
  id-token: write
jobs:
  check:
    runs-on: ubuntu-latest
    env:
      IPSO_URL: https://ipso.example.com
      IPSO_CI_AUDIENCE: https://ipso.example.com/ci
    steps:
      - uses: actions/checkout@<sha>
      - run: ipso check plan plan.json --env prod --report report.json --sarif ipso.sarif
      - if: always()
        run: |
          token=$(curl -sS -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
            "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${IPSO_CI_AUDIENCE}" | jq -r .value)
          jq -n --slurpfile report report.json --arg sarif "$(sha256sum ipso.sarif | cut -d' ' -f1)" \
            '{check: "plan", report: $report[0], sarif_sha256: $sarif}' > upload.json
          curl -sS --fail-with-body --retry 5 -X POST "${IPSO_URL}/v1/verdicts" \
            -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" --data-binary @upload.json
```

The answer is 201 with the id of the upload, or 200 with the id of the first one when the same run, attempt and content had already been uploaded. A repeat adds nothing. Another attempt of the run, or other content from the same attempt, is a new upload, because a matrix job shares one run id. A body over 1 MiB is 413 and nothing is stored. The upload takes no query. It shares the tenant's request budget with the reads, so a matrix of many jobs can be answered 429 with `Retry-After`, and the `--retry` of the example makes curl wait and try again.

## Read the results

`GET /v1/verdicts` lists the stored verdicts of the tenant, newest first, as a person with a bearer token or a session. It takes `repo` (owner/name, in any case), `decision` (an EDR id or a slug), `limit` and `before`, as the other lists do. Each item is one decision check with the run it came from: the repository, commit, ref, event, workflow, run and its link, the check, the environment, the times, the report and SARIF digests, and the hashes, paths and engine version that only that check's report has. Any role of the tenant can read it ([docs/roles.md](roles.md)).

The list is read as known at a time. `known` is the transaction time, absent means now, and the answer echoes the time it used: only the uploads the server had stored by then are listed. A verdict whose report carried digests is read against the baseline that a person recorded for its decision and repository ([docs/web-app.md](web-app.md)), and `baseline` on the item says the result: `waived(baseline)` when the baseline holds every digest the run sent, and `fail` otherwise, with the number sent and the number held. `baseline` is null when the run sent no digest. `result` stays what the run reported, so a reader sees both, and a local file that disagrees with the registry shows as a `waived` run that reads `fail`.

The reading is made when the verdict is read and is never stored. The decision is the one whose body holds the EDR id of the verdict, as known at `known`, and an id that no decision holds or that two hold reads `fail`. The grandfather period has to cover the time the server stored the upload, not the `evaluated_at` that the runner states, so a deadline is read by the server's clock. A baseline or a waiver recorded after an answer was read as known before it does not change that answer. Audit question Q3 still has no verdicts, and the server computes no `decisions_in_force_snapshot_hash` ([ADR-0123](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0123-waivers-on-verdict-reads.md)).

A verdict that is a `fail` or a `waived` is also read against the waivers recorded for its decision ([docs/web-app.md](web-app.md)), and `waiver` on the item says the result: `waived` with `expires_at`, the latest end among the waivers that cover it, or `fail` with a null `expires_at`. `waiver` is null when the run reported `pass` or `error`, because a pass has nothing to waive and a waiver never covers an error. A run that reported `waived` is read like a `fail`, so a waiver written into the decision file of the repository shows as `waived` in the run and reads `fail` here until a person records it. The valid time is the time the server stored the upload, as for the baseline. A waiver covers a verdict when its scope covers every path of the repository, so a waiver of a path never covers one, because a report holds no path, a waiver of an environment covers a run that names that environment and no other, and an environment that is not a registry name reads as none. The reason, the approver, the ticket and the id of a waiver are not in the answer.

## Failures

| Status | Meaning |
| --- | --- |
| 400 | The body is not a report of its command, or has a field the contract does not list, or the query is not empty |
| 401 | No bearer token, or one that is not a valid GitHub Actions token for the audience |
| 403 | No installation of this server's tenant covers the repository |
| 413 | The body is over 1 MiB |
| 415 | The body is not `application/json` |
| 429 | The tenant has no calls left, or the server makes too many calls to GitHub for repositories it has not seen lately |
| 503 | GitHub or the database could not say which tenant owns the repository |
