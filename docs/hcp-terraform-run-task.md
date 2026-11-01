# HCP Terraform run task

`ipso-server runtasks` is a run task for HCP Terraform and Terraform Enterprise. It reads the plan of a run, evaluates it against a signed policy bundle with the rules of `ipso check plan`, and reports the result to the run. The contract is ADR-0065 in `ipsofacto-io/ipso-spec`. The service has no database and no tenant data, and one service holds one bundle.

## Build the bundle

Compile and sign your decisions in a job you trust, with the [`ipso` CLI](https://github.com/ipsofacto-io/ipso):

```sh
ipso compile
ipso bundle pack --layout bundle
ipso bundle sign --layout bundle --key private.pem
```

`pack` prints the digest. Give the service the layout, that digest, and the public key. The service verifies them at start and refuses to run on an unsigned layout, another digest, or a bad signature. Restart it to move to a new bundle.

## Run the service

```sh
IPSO_RUNTASK_HMAC_KEY=<key> \
IPSO_RUNTASK_BUNDLE=/etc/ipso/bundle \
IPSO_RUNTASK_BUNDLE_DIGEST=sha256:<digest> \
IPSO_RUNTASK_BUNDLE_PUBLIC_KEY=/etc/ipso/bundle.pub \
ipso-server runtasks
```

| Variable | Meaning |
| --- | --- |
| `IPSO_RUNTASK_HMAC_KEY` | The HMAC key of the run task, at least 32 bytes |
| `IPSO_RUNTASK_BUNDLE` | The signed OCI layout |
| `IPSO_RUNTASK_BUNDLE_DIGEST` | The pinned manifest digest, `sha256:<hex>` |
| `IPSO_RUNTASK_BUNDLE_PUBLIC_KEY` | The public key that verifies the bundle |
| `IPSO_RUNTASK_ENV` | Optional. Limits the checks to one environment, as `--env` does |
| `IPSO_RUNTASK_HOST` | Optional. The API host, `app.terraform.io` by default. Set it for Terraform Enterprise or another HCP region |
| `IPSO_RUNTASK_PLAN_HOSTS` | Optional. Comma-separated hosts a plan download may redirect to, `archivist.terraform.io` by default. Set it with `IPSO_RUNTASK_HOST` |
| `IPSO_LISTEN_ADDR` | Listen address, `:8080` by default |

The listener speaks plain HTTP, so put TLS and a rate limit in front of it. HCP Terraform has to reach the host over HTTPS. `GET /healthz` answers 204. It says nothing about HCP Terraform.

## Create the run task

In the organization's **Settings > Run tasks**, create a task:

| Setting | Value |
| --- | --- |
| Endpoint URL | `https://<host>/runtasks/hcp-terraform` |
| HMAC key | The value of `IPSO_RUNTASK_HMAC_KEY` |

HCP Terraform sends a test request when you save, and the service answers 200 to it. Then attach the task to a workspace:

| Setting | Value |
| --- | --- |
| Run stage | Post-plan, or pre-apply |
| Enforcement level | **Mandatory** |

The enforcement level decides whether the run stops. With **Advisory**, HCP Terraform shows a failed result as a warning and lets the apply go on. On any other stage the service reports a failure that asks you to move the task.

## What the run shows

| Result | Run task status | What the run does |
| --- | --- | --- |
| A block-mode check has a violation that nothing covers | `failed` | A mandatory task stops the apply |
| A check fails to evaluate, or the plan cannot be read | `failed` | The same. The service fails closed |
| A warn-mode or advise-mode check has a violation | `passed` | The apply can go on, and the outcome shows the warning |
| A waiver or a baseline covers a violation | `passed` | The apply can go on, and the outcome shows `Waived` |
| No check applies | `passed` | The message says `no checks selected` |

An outcome names the check and lists up to 50 resource addresses. It carries no violation message, because a message can quote an attribute. Sensitive values stay out of the plan output readers of the run can see, and the JSON plan this service reads holds them in the clear. To read the messages, run `ipso check plan` on the plan where you are allowed to see it.

If the service cannot reach the callback, it tries three times. After that it reports nothing, and HCP Terraform times the task out after 10 minutes. A mandatory task then stops the apply.

## What the service holds

- The access token of a run stays in memory for that job. It goes only to `IPSO_RUNTASK_HOST`, and a redirect is never followed with it.
- The plan stays in memory for that job, and it is never written to disk or logged. The log holds the plan hash, the number of checks, and the number that failed. A plan is at most 256 MiB, and four jobs run at a time, so size the memory for that.
- The HMAC key and the access token are not logged. Neither are plan URLs, because a download URL is a credential.
- A request without a valid signature is answered 401 before anything reads it.

## Validate it on a real workspace

The tests run against a fake API that follows the published contract. They have not run against HCP Terraform, because that needs an organization and a public host. To validate the service:

1. Run it on a public host and create the task. The save only succeeds if the test request gets a 200.
2. Attach it to a workspace at post-plan with mandatory enforcement.
3. Start a run with a plan that breaks a blocking decision. The task should show `failed`, the outcome should list the resource, and the apply should not be available.
4. Start a run that breaks only a warning decision. The task should show `passed`, the outcome should show the warning, and the apply should be available.
5. Send a request with a wrong `X-TFC-Task-Signature`. The answer should be 401.
