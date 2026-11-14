# Web app

The web app is the browser view of the control plane: the registry, the review queues, the waivers and the audit questions, and the actions a person takes on them: approve or reject a draft or a drafted check, record a waiver, record a supersession, clear a premise review reason. An admin also changes the premise allowlist and starts and downloads the export of the tenant. It is a React, Vite and TypeScript single-page app in [web/](../web), built into the `ipso-server` binary and served by the `api` role ([ADR-0106](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0106-web-app-stack-and-serving.md)). It looks like the rest of ipso because it uses the brand kit as its visual system ([ADR-0107](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0107-brand-kit-visual-system.md)).

## What it shows

| Path | View |
| --- | --- |
| `/decisions` | The decisions in force, with their state, owner, criticality and review date. Filter the ones loaded, and ask for another valid or known time. |
| `/decisions/{id}` | One decision: its record, scope, checks, premises and sources, the CI verdicts reported on it, each as the recorded waivers and the recorded baseline read it, with the day a covering waiver ends and what the run reported beside it when the two differ, and the decision that replaced it when it is superseded. It links to the forms to record a waiver for it and to supersede it. |
| `/scopes` | The scope tree. |
| `/inbox` | The three review queues: decisions a model found in pull requests, decisions your coding agents proposed, and checks drafted for a decision. A draft of the first two has Approve and Reject, and so has a drafted check, which records the answer only. |
| `/waivers` | The waivers in force, in words: "Expires in 3 days". |
| `/premises` | The open review reasons of the premises, each with the fail that opened it (the URL, the pointer, the expected and the observed value, shown as text), and the hosts a premise probe may dial. A reason has Clear, and a host has Withdraw or Allow again, with a field to allow a host. |
| `/waivers/new` | The form to record a waiver. `?decision=` names the decision. |
| `/supersessions/new` | The form to record a supersession and the grandfather terms of the new decision. `?from=` names the decision that ends. |
| `/baselines/new` | The form to record the baseline of one repository for a decision that has grandfather terms, from the file that `ipso baseline export` writes. `?decision=` names the decision. |
| `/export` | The export of the tenant, for an admin: a field for one age public key, the state of the export (pending, running, ready, failed) and its expiry, and the download of the archive once it is ready. A person without the role reads the refusal and no form. |
| `/audit` | The five questions of section 2.3: what applied, what changed, at a merge, supersessions, and waivers ending soon. The fields are in the address, so an answer can be shared. |
| `/signin` | The sign-in. Any call the server refuses with 401 ends here. |

Importing decisions and compiling them into checks (UC1 and UC2) have no API route, so they stay in the CLI. Delivering an accepted check to a repository, running a premise probe on demand, and creating a scope or changing the role of a person are not in the app either.

## Taking an action

The actions are the write routes of [ADR-0109](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0109-control-plane-write-routes.md), and the app follows [ADR-0110](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0110-web-app-write-actions.md) for a drafted check, [ADR-0118](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0118-web-app-check-answer.md), and for the premises page, [ADR-0119](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0119-web-app-premises.md).

| Action | Where | Route | Who |
| --- | --- | --- | --- |
| Approve a draft | A card of the inbox | `POST /v1/proposals/{id}/approval` or `POST /v1/agent-proposals/{id}/approval` | Approver or decision owner, over every scope the decision names |
| Reject a draft | A card of the inbox | the same, with `{"outcome":"rejected"}` | Approver or decision owner over the whole tenant |
| Approve or reject a drafted check | A card of the inbox | `POST /v1/decisions/{decisionID}/check-proposals/{id}/approval` | Approver or decision owner, over every scope of the decision the check is for, for either outcome |
| Clear a premise review reason | A card of `/premises` | `POST /v1/decisions/{decisionID}/premises/{premiseID}/clearance` with `{}` | Decision owner, over every scope of the decision |
| Allow or withdraw a host | `/premises` | `POST /v1/premise-hosts` with `{"host":...,"allowed":...}` | Admin |
| Record a waiver | `/waivers/new` | `POST /v1/waivers` | Approver or decision owner over the scope of the waiver |
| Record a supersession | `/supersessions/new` | `POST /v1/supersessions`, then `POST /v1/decisions/{id}/grandfather-period` for the new decision | Decision owner over every scope of both decisions |
| Record a baseline | `/baselines/new` | `POST /v1/decisions/{decisionID}/baselines` | Decision owner over every scope of the decision |

A coding agent cannot take any of these: the role policy refuses it before the server reads the request, and a browser session always belongs to a person. No route says what role a person holds, so the app shows every action to every signed-in person and says in words, after the call, when no role allows it. Nothing is optimistic: the queue reads again after a write, a draft leaves it only if the server answered, and a 409 says that someone answered first.

An approval writes the decision as an EDR with all sixteen keys of draft 0.2, so a verdict, the detail view and the MCP tools read it the way they read any other. The person gives the owner (`team:name`), the slug, the dates, the criticality, a source link and the scopes. The draft's statement and rationale have no key in the EDR and stay with the proposal. A waiver lasts at most 90 days ([ADR-0054](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0054-waivers-with-expiry.md)), and the form says so before it sends. A supersession closes the old decision at the instant given, and no route removes it, so the form says that above the button. The grandfather terms say how long a recorded baseline counts: none, no end, or a deadline. When the supersession is recorded and the terms are refused, the page says so and sends only the terms again.

A baseline is recorded from the decision, one repository at a time, with the file that `ipso baseline export <EDR id>` writes in the checkout ([ADR-0121](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0121-baseline-upload.md)). The file holds the fingerprints and no salt, so the page never sees what the repository keeps. The page refuses a file made for another decision, a fingerprint that is not 64 lowercase hexadecimal characters, and a baseline that does not fit the 1 MiB of a request, about 15,600 fingerprints, before it sends anything. A decision has one baseline for a repository, the app cannot change or remove it, and the page says so above the button. A recorded baseline is applied to the verdicts of a CI run when they are read, and the decision page shows the reading ([ADR-0122](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0122-baseline-on-verdict-reads.md)).

A drafted check has no form, because the answer is an outcome and writes no decision: each outcome is one confirmation and one request, and the confirmation says that the answer is recorded once. An approved check reaches a repository only when someone runs `ipso deliver` there, with the answer of `GET /v1/accepted-checks` ([ADR-0120](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0120-accepted-check-delivery.md)), and a rejected rule is not drafted again for the same version of the decision ([ADR-0116](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0116-check-proposal-approval.md), ADR-0118).

The premises page reads `GET /v1/premise-reasons` and `GET /v1/premise-hosts` (ADR-0117), which every role may read, so the menu always has the entry. A reason is shown with the fail that opened it as the evaluation stored it, and the observed value came from a public URL, so it is shown as text and never as markup. A clearance is one confirmation and one request, and it records that an owner looked: it does not change the decision, and a later fail opens a new reason. An allow and a withdraw are one request each with no confirmation, because each undoes the other, and a withdrawn host stays listed so it can be allowed again. The field checks a host the way the server does (a DNS name in lowercase ASCII, in punycode when it is not, never an address) before it sends, and the form and the host actions are shown only when the read of the allowlist was not refused (ADR-0119).

Every action sends only the body. The tenant, the principal and the approver come from the session cookie, and a key for any of them is a 400 (ADR-0099, ADR-0109).

### The export

The export screen follows [ADR-0115](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0115-web-app-export-screen.md) and the routes of [ADR-0111](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0111-tenant-export-through-the-api.md). Only an admin who is a person takes them, and the menu follows the server's answer: the app reads `GET /v1/exports/current` once when a session starts and shows the entry "Export" after any answer but a 401 or a 403. The page opens with the same read, so it survives a reload and a second admin finds the export that is under way. It reads again every five seconds while the export is pending or running.

The key field takes one age public key. A private key (it starts with `AGE-SECRET-KEY-`) is never sent: the field is cleared and the page says so. Every other check is the server's, and a key it cannot read shows its 400 in words and is never quoted. The download is a link to `/v1/exports/{id}/archive` that opens in a new tab, where the attachment header makes the browser save the file, so the page never holds the archive. The page holds a public key and an export id and nothing else of the export.

A decision is shown in the brand's four states, always with a word and an icon: Verified, Verifying, Needs review and Rejected. A proposed decision is Verifying with a "Pending approval" label, and a superseded or deprecated decision is a plain label. The color of Verified is used for nothing else.

## How it is served

`internal/webapp` embeds the build (`internal/webapp/dist/app`) and serves it at every path that is not the API's (`/v1/`) or the sign-in's (`/auth/`). A path of a file in the build is that file (the text files gzipped once at start and sent to a client that accepts it), a path under `/assets/` or with a file extension that is not there is a 404, and any other path is the page, because the app draws the view from the address. A binary built without the web app (`go build` with no `npm run build` before it) still serves the API, and `/` says the app is not built in.

Every answer of the app carries this policy and these headers:

```text
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
X-Frame-Options: DENY
```

The policy lets a page load and call only its own origin, so the page has no inline script or style and the fonts are served from the app (`@fontsource`, SIL Open Font License) and not from Google Fonts. HSTS belongs to the TLS front of a deployment.

## Signing in

The app uses the session cookie of [ADR-0099](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0099-browser-login-sessions.md) and nothing else: the page and the API are one origin, the cookie is HttpOnly and SameSite=Strict, and a request that could change state from another origin is refused by the server. The app holds no token and sends no tenant, because the tenant is the one the process serves. `GET /auth/providers` lists the providers the server is configured with, so the sign-in page links to `/auth/login/{id}`. A 401 sends the person to the sign-in, a 429 only says to try again, and a 403 says no role of the person allows it and to ask a tenant admin for one (ADR-0108).

The sign-in answers of `/auth` that a person sees directly (a refused callback, an unknown login) are JSON pages of the server, not views of the app.

## Develop

Node 24 and npm. Everything is in [web/](../web):

```sh
cd web
npm ci
npm run fixtures     # the app over a stand-in API, no database and no identity provider
npm run dev          # the app on :5173, proxying /v1 and /auth to the Compose stack on :8080
npm run typecheck
npm test
npm run build        # writes internal/webapp/dist/app, which go build embeds
```

`npm run fixtures` serves records from [web/fixtures](../web/fixtures) with the rules of the real API that a client can break (a 401 without a session, a 400 for a query key a route does not list or a body key it does not list, a 90-day limit on a waiver, a draft or a drafted check answered once, a review reason cleared once, a host that must be a DNS name). A write changes what it serves until it stops, so an answered draft or drafted check leaves its queue and a cleared reason leaves the premises page. It does not play the role policy: every person may write there. It plays the export routes too: an export asked for there is pending for a few seconds, then running, then ready, and the download is a small stand-in file, so the whole flow can be seen at `/export`. Opening `/auth/login/dex` signs in there, and `POST /auth/logout` signs out. `npm run dev` needs a session on the stack: sign in at `http://localhost:8080/auth/login/dex` once ([local-stack.md](local-stack.md)), and `http://localhost:5173` shares the cookie, because a cookie does not name a port.

`npm ci` runs no install script (`web/.npmrc`). The types of the API are generated from [api/openapi.yaml](../api/openapi.yaml) into `web/src/api/schema.d.ts` with `npm run api:types`, and `npm run api:check` fails when the committed file is behind the document.

## The contract

The web app writes its own contract. `npm run test:pact` plays each call of `web/src/api/calls.ts`, the writes included, against a Pact mock server and writes [api/pacts/ipso-web-ipso-server.json](../api/pacts/ipso-web-ipso-server.json), and the Go provider test verifies it against the handler on PostgreSQL ([ADR-0091](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0091-api-contract-tests-and-pact.md)). `ci / pact` fails when the committed file differs from what the tests write. Change a call, run `npm run test:pact`, and commit the file. A write changes what the provider holds, so each provider state of a write seeds its own rows and returns their ids (`internal/api/pact_provider_integration_test.go`), and the interaction names them with `fromProviderState`.

## The brand kit

The brand kit is a private repository, `ipsofacto-io/ipso-brand-kit`, and this repository is public, so the app copies what it needs at a pinned commit instead of fetching it at build time. `web/src/brand` holds the kit's `src/` without `styles/fonts.css`, and `web/public` holds its favicon, app icons and manifest. [web/src/brand/PROVENANCE.md](../web/src/brand/PROVENANCE.md) names the commit and the command that copies it. To take a change of the identity, change the kit first, then repeat the command at the new commit and record it.

The kit's rules apply in the app: the wordmark is never retyped with a font, the cursor blinks only while a request is in flight, the mascot never carries a state alone, and the name in running text is a plain lowercase "ipso".

## Checks

`ci / web` installs, typechecks, runs the unit tests, checks the API types, builds, and then has the Go handler read the build it made. `ci / licenses` also checks the licenses of the packages that ship in the app (the ones that are not dev dependencies). `ci / compose` asks the stack through its front for the page, a view by its address, the files of the build and the headers, and checks that the API and the sign-in answer as before.
