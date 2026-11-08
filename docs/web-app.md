# Web app

The web app is the browser view of the control plane: the registry, the review queues, the waivers and the audit questions. It is a React, Vite and TypeScript single-page app in [web/](../web), built into the `ipso-server` binary and served by the `api` role ([ADR-0106](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0106-web-app-stack-and-serving.md)). It looks like the rest of ipso because it uses the brand kit as its visual system ([ADR-0107](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0107-brand-kit-visual-system.md)).

## What it shows

| Path | View |
| --- | --- |
| `/decisions` | The decisions in force, with their state, owner, criticality and review date. Filter the ones loaded, and ask for another valid or known time. |
| `/decisions/{id}` | One decision: its record, scope, checks, premises and sources, the CI verdicts reported on it, and the decision that replaced it when it is superseded. |
| `/scopes` | The scope tree. |
| `/inbox` | The three review queues: decisions a model found in pull requests, decisions your coding agents proposed, and checks drafted for a decision. |
| `/waivers` | The waivers in force, in words: "Expires in 3 days". |
| `/audit` | The five questions of section 2.3: what applied, what changed, at a merge, supersessions, and waivers ending soon. The fields are in the address, so an answer can be shared. |
| `/signin` | The sign-in. Any call the server refuses with 401 ends here. |

The app is read-only. The API has its write routes (IPSO-134, [ADR-0109](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0109-control-plane-write-routes.md)), and IPSO-146 adds the approve, waiver and supersession actions to the app. Until then approving a draft, recording a waiver and recording a supersession happen in the pull request, with the CLI or with the API, and the inbox says so. Importing decisions and compiling them into checks (UC1 and UC2) have no API route either.

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

`npm run fixtures` serves records from [web/fixtures](../web/fixtures) with the rules of the real API that a client can break (a 401 without a session, a 400 for a query key a route does not list). Opening `/auth/login/dex` signs in there, and `POST /auth/logout` signs out. `npm run dev` needs a session on the stack: sign in at `http://localhost:8080/auth/login/dex` once ([local-stack.md](local-stack.md)), and `http://localhost:5173` shares the cookie, because a cookie does not name a port.

`npm ci` runs no install script (`web/.npmrc`). The types of the API are generated from [api/openapi.yaml](../api/openapi.yaml) into `web/src/api/schema.d.ts` with `npm run api:types`, and `npm run api:check` fails when the committed file is behind the document.

## The contract

The web app writes its own contract. `npm run test:pact` plays each call of `web/src/api/calls.ts` against a Pact mock server and writes [api/pacts/ipso-web-ipso-server.json](../api/pacts/ipso-web-ipso-server.json), and the Go provider test verifies it against the handler on PostgreSQL ([ADR-0091](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0091-api-contract-tests-and-pact.md)). `ci / pact` fails when the committed file differs from what the tests write. Change a call, run `npm run test:pact`, and commit the file.

## The brand kit

The brand kit is a private repository, `ipsofacto-io/ipso-brand-kit`, and this repository is public, so the app copies what it needs at a pinned commit instead of fetching it at build time. `web/src/brand` holds the kit's `src/` without `styles/fonts.css`, and `web/public` holds its favicon, app icons and manifest. [web/src/brand/PROVENANCE.md](../web/src/brand/PROVENANCE.md) names the commit and the command that copies it. To take a change of the identity, change the kit first, then repeat the command at the new commit and record it.

The kit's rules apply in the app: the wordmark is never retyped with a font, the cursor blinks only while a request is in flight, the mascot never carries a state alone, and the name in running text is a plain lowercase "ipso".

## Checks

`ci / web` installs, typechecks, runs the unit tests, checks the API types, builds, and then has the Go handler read the build it made. `ci / licenses` also checks the licenses of the packages that ship in the app (the ones that are not dev dependencies). `ci / compose` asks the stack through its front for the page, a view by its address, the files of the build and the headers, and checks that the API and the sign-in answer as before.
