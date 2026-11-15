# GitHub App

`ipso-server webhooks` is the service behind the ipso GitHub App. The contract is [ADR-0061](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0061-github-app.md) in `ipsofacto-io/ipso-spec`, which [ADR-0101](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0101-installation-tenant-mapping.md) supersedes in one point: the service opens the database as the application role to ask which tenant owns the installation of a delivery. [ADR-0103](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0103-pr-proposals-in-the-webhooks-process.md) supersedes ADR-0101 in one more point: when an LLM gateway is configured, the service also writes decision proposals and token use for that tenant. It validates the decision files of a change and annotates the invalid ones in a check run. It does not run engine checks, which stay with [`ipso-action`](https://github.com/ipsofacto-io/ipso-action).

## Register the App

Registration happens in the browser, under the organization's **Settings > Developer settings > GitHub Apps > New GitHub App**. Use exactly these settings. The service reads them back at start and refuses to run on any other permission set.

| Setting | Value |
| --- | --- |
| Webhook URL | `https://<host>/webhooks/github` |
| Webhook secret | At least 32 random bytes |
| Repository permission: Checks | Read and write |
| Repository permission: Contents | Read-only |
| Repository permission: Metadata | Read-only |
| Repository permission: Pull requests | Read and write |
| Subscribe to events | Pull request, Push |
| Where can this App be installed | Only on this account, while it is in the sandbox |

Do not add any other permission. An ADR comes first for anything beyond section 3.1.

Then generate a private key and keep it in your secret store.

## Bind an installation to its tenant

A delivery names an installation and no tenant, and the service takes the tenant from the database and never from the payload. An installation that no tenant owns is refused with 403 and starts nothing. After the App is installed on an account, find the installation id in the URL of its settings page (`https://github.com/settings/installations/<id>` for a user account, `https://github.com/organizations/<org>/settings/installations/<id>` for an organization), and bind it:

```sh
IPSO_DATABASE_URL=postgres://ipso_app:...@db.example/ipso \
IPSO_GITHUB_APP_ID=<app id> \
IPSO_GITHUB_APP_PRIVATE_KEY="$(cat app.pem)" \
ipso-server tenant bind-installation --tenant <tenant id> --installation <id> --account <login>
```

The command asks GitHub, as the App, which account the installation is on, and binds nothing unless it belongs to this App and its account is the `--account` you gave. An installation belongs to one tenant: a second tenant's bind is refused, and binding the same pair again changes nothing. A tenant may hold several installations. `ipso-server tenant offboard` removes a tenant's bindings, and the service removes the binding of an installation that its account uninstalls ([ADR-0125](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0125-installation-unbind-on-uninstall.md)). A delivery that GitHub refused before the bind can be redelivered from the App's advanced settings. The same binding decides which tenant the verdicts of a CI job are stored under ([docs/verdicts.md](verdicts.md)).

## Run the service

```sh
IPSO_DATABASE_URL=postgres://ipso_app:...@db.example/ipso \
IPSO_GITHUB_APP_ID=<app id> \
IPSO_GITHUB_APP_PRIVATE_KEY="$(cat app.pem)" \
IPSO_GITHUB_WEBHOOK_SECRET=<secret> \
ipso-server webhooks
```

| Variable | Meaning |
| --- | --- |
| `IPSO_DATABASE_URL` | The database, as the application role. The service refuses to start as a superuser, a role that bypasses row-level security, or a table owner, when the migration credential is also set, or when the database was not migrated |
| `IPSO_GITHUB_APP_ID` | The numeric App ID |
| `IPSO_GITHUB_APP_PRIVATE_KEY` | The private key as PEM, PKCS#1 or PKCS#8 |
| `IPSO_GITHUB_WEBHOOK_SECRET` | The webhook secret, at least 32 bytes |
| `IPSO_LISTEN_ADDR` | Listen address, `:8080` by default |
| `IPSO_GATEWAY_CONFIG` | Optional. The path of the LLM gateway configuration, a JSON file. When it is set, a merged pull request is turned into decision proposals. Without it no discussion is read and no model is called. The service stops at start when the file is wrong or a route's key is missing |
| `IPSO_LLM_<NAME>` | The key of one route, named by the `key_env` of that route in the file. The file holds no key |

The listener speaks plain HTTP, so put TLS and a rate limit in front of it. `GET /healthz` answers 204. It says nothing about GitHub.

## Turn on decision proposals

A merged pull request can leave pending decision proposals in the inbox of its tenant ([ADR-0062](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0062-pr-decision-proposals.md), [ADR-0103](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0103-pr-proposals-in-the-webhooks-process.md)). Set `IPSO_GATEWAY_CONFIG` to a file like this one, and the key of each route in the variable it names:

```json
{
  "routes": [
    {"name": "mistral", "provider": "mistral", "model": "mistral-medium-latest", "key_env": "IPSO_LLM_MISTRAL"}
  ],
  "default": ["mistral"],
  "monthly_tokens": 2000000
}
```

The routes you list must be EU-resident, and a tenant can bring its own under `tenants` ([ADR-0081](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0081-llm-gateway.md), [ADR-0014](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0014-eu-only-llm-routes-by-default.md)). The service needs the migrations applied, because the gateway keeps each tenant's monthly budget in `llm.usage`. The webhooks process then holds the keys of your routes, calls them from the internet-facing process, and writes `proposals.proposal` and `llm.usage` as the application role.

When a pull request merges, the service reads its body, conversation comments, review summaries, and review comments with a token limited to `pull_requests:read` and `metadata:read` for that repository. Only the comments of owners, members, and collaborators that read as a decision, hold no injection marker, and link to this pull request go to the model, with secrets and email addresses redacted. Each valid answer becomes a proposal that can only be pending, with the link of the comment it came from. A person reviews it in the inbox (`GET /v1/proposals` on the api role), and nothing here approves one.

The job runs on two workers of its own, so a slow model never delays a check run, and it is bounded to 15 minutes. A job that fails, such as one over the tenant's budget or one whose routes are all down, is forgotten, and a redelivery from the App's advanced settings runs it again. The comments already turned into proposals are not sent again. The log of a finished job holds counts only.

## Check the sandbox install

1. Install the App on one repository of a sandbox organization, and bind the installation to a tenant as above.
2. Open a pull request that adds an invalid file under `docs/decisions/`, such as one holding only `not a record`.
3. The pull request shows the failed check `ipso / decisions` with an annotation on that file.
4. Fix the file and push. The check passes.
5. Add any permission to the App and restart the service. It refuses to start.

## What happens on an event

| Event | Work |
| --- | --- |
| `pull_request` opened, synchronize, reopened | One check run on the head commit, over the files of the pull request |
| `push` to the default branch | One check run on the new commit, over the files since the previous commit |
| `pull_request` closed and merged, with `IPSO_GATEWAY_CONFIG` set | The discussion is read and turned into pending proposals for the tenant of the installation |
| `installation` deleted | The service asks GitHub, as the App, whether the installation is gone, and if it is, removes its binding before it answers |
| Anything else | Answered with 202, no work |

A delivery that would start work is answered 403 when its installation has no tenant, and 503 when the database cannot be asked, so GitHub records a failed delivery that can be redelivered. Neither is remembered, so the redelivery after a bind is worked.

GitHub sends `installation` events to every App, and an App cannot subscribe to them, so registering the App needs no setting for them. An uninstall is answered 202 when the binding is removed and when the installation had none. It is answered 503, and nothing is removed, when GitHub or the database cannot answer, or when GitHub still has the installation, so a failed removal can be redelivered. A suspended installation keeps its binding.

A run that cannot finish concludes as a failure with fixed text, and the service log names the reason. A delivery that repeats within the last 4096 does no work, and a job that failed can be retried with a redelivery.
