# GitHub App

`ipso-server webhooks` is the service behind the ipso GitHub App. The contract is ADR-0061 in `ipsofacto-io/ipso-spec`. It validates the decision files of a change and annotates the invalid ones in a check run. It has no database and no tenant data. It does not run engine checks, which stay with [`ipso-action`](https://github.com/ipsofacto-io/ipso-action).

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

## Run the service

```sh
IPSO_GITHUB_APP_ID=<app id> \
IPSO_GITHUB_APP_PRIVATE_KEY="$(cat app.pem)" \
IPSO_GITHUB_WEBHOOK_SECRET=<secret> \
ipso-server webhooks
```

| Variable | Meaning |
| --- | --- |
| `IPSO_GITHUB_APP_ID` | The numeric App ID |
| `IPSO_GITHUB_APP_PRIVATE_KEY` | The private key as PEM, PKCS#1 or PKCS#8 |
| `IPSO_GITHUB_WEBHOOK_SECRET` | The webhook secret, at least 32 bytes |
| `IPSO_LISTEN_ADDR` | Listen address, `:8080` by default |

The listener speaks plain HTTP, so put TLS and a rate limit in front of it. `GET /healthz` answers 204. It says nothing about GitHub.

## Check the sandbox install

1. Install the App on one repository of a sandbox organization.
2. Open a pull request that adds an invalid file under `docs/decisions/`, such as one holding only `not a record`.
3. The pull request shows the failed check `ipso / decisions` with an annotation on that file.
4. Fix the file and push. The check passes.
5. Add any permission to the App and restart the service. It refuses to start.

## What happens on an event

| Event | Work |
| --- | --- |
| `pull_request` opened, synchronize, reopened | One check run on the head commit, over the files of the pull request |
| `push` to the default branch | One check run on the new commit, over the files since the previous commit |
| Anything else | Answered with 202, no work |

A run that cannot finish concludes as a failure with fixed text, and the service log names the reason. A delivery that repeats within the last 4096 does no work, and a job that failed can be retried with a redelivery.
