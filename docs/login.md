# Sign in with an identity provider

A person signs in to the control plane in a browser through an identity provider: Google, Microsoft, GitHub, or the provider of a self-hosted install. ipso-server is a relying party and nothing more ([ADR-0099](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0099-browser-login-sessions.md)). It runs the authorization code flow with PKCE, `state`, and a nonce, then keeps a session of its own. It stores no password and no profile, so there are no local accounts. Multi-factor authentication is the provider's policy: 2-Step Verification in Google Workspace, Conditional Access in Entra ID, or the rules of your own provider.

The bearer tokens of the API and of remote MCP are unchanged. A request that carries an `Authorization` header is always a bearer call. The session cookie is read only when there is no such header, and only when sign-in is configured.

## Turn it on

Two settings of `ipso-server --role=api` turn on sign-in, and they are set together or not at all.

- `IPSO_PUBLIC_URL` is the origin people reach the control plane at, such as `https://ipso.example.com`. It is https, or http for `localhost`, `127.0.0.1`, and `[::1]` only, and it has no path. Redirect URIs and the cross-origin check are built from it, never from a request header.
- `IPSO_LOGIN_PROVIDERS` is a JSON array of providers. A provider names the environment variable that holds its client secret, so the JSON is safe to log and to commit.

```json
[
  {"id": "google", "kind": "oidc", "issuer": "https://accounts.google.com", "client_id": "1234.apps.googleusercontent.com", "client_secret_env": "IPSO_LOGIN_GOOGLE_SECRET"},
  {"id": "microsoft", "kind": "oidc", "issuer": "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0", "client_id": "00000000-0000-0000-0000-000000000001", "client_secret_env": "IPSO_LOGIN_MICROSOFT_SECRET"},
  {"id": "github", "kind": "github", "client_id": "Iv1.abcdef", "client_secret_env": "IPSO_LOGIN_GITHUB_SECRET"}
]
```

Each provider has an `id`, which is the last part of its redirect URI: `{IPSO_PUBLIC_URL}/auth/callback/{id}`. Register that exact URI with the provider. `kind` is `oidc` for a provider that returns an ID token and `github` for GitHub's OAuth 2.0 sign-in, which returns none. The secret variable starts with `IPSO_LOGIN_` and must be set.

The process refuses to start when a provider cannot be discovered over https, when two providers share an id or an issuer, when there is more than one GitHub provider, when a `client_id` equals the audience of the API or of remote MCP, or when the public URL is not an origin. A provider that is down at start stops the process, so a login that does not work is never served.

## Register the application

Sign-in asks for no scope other than `openid`, and GitHub for none at all.

- **Google.** In the Google Cloud console, create an OAuth client of the type Web application and add `{IPSO_PUBLIC_URL}/auth/callback/google` as an authorized redirect URI. The issuer is `https://accounts.google.com`. Require 2-Step Verification in Google Workspace if you need MFA.
- **Microsoft.** In Entra ID, register an application with the Web platform and the redirect URI `{IPSO_PUBLIC_URL}/auth/callback/microsoft`, and create a client secret. Use the issuer of your directory, `https://login.microsoftonline.com/{directory id}/v2.0`. The multi-tenant `common` endpoint is refused, because its tokens name the directory of the person and not `common`. A Microsoft `sub` is unique per application: a new registration changes every subject, and every login must then be bound again. Enforce MFA with Conditional Access.
- **GitHub.** Create an OAuth App with the callback URL `{IPSO_PUBLIC_URL}/auth/callback/github`. The subject is the numeric id of the user and never the user name, which can be renamed. GitHub cannot assert MFA in a token. A deployment that must enforce MFA leaves GitHub off or binds only members of an organization that requires two-factor authentication. GitHub Enterprise Server is not supported.
- **Your own provider.** Any OpenID Connect provider that publishes metadata at `/.well-known/openid-configuration` (or RFC 8414) and keys over https works. Register `{IPSO_PUBLIC_URL}/auth/callback/{id}` with it. The local stack uses Dex this way.

## Invite a person

A sign-in becomes a session only for a login the tenant has bound to a person ([ADR-0093](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0093-single-tenant-token-mapping.md)). `ipso-server tenant create` binds the first person of a tenant ([docs/tenants.md](tenants.md)), and an admin invites everyone after that ([ADR-0127](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0127-invitations.md)).

An admin who is a person makes an invitation with a name and one role, over the whole tenant. The web app does the same from its Invitations page ([docs/web-app.md](web-app.md#the-invitations)), and the three calls below are the ones it makes:

```sh
curl -sS -X POST "$IPSO/v1/invitations" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"name":"Ada","role":"viewer"}'
```

The answer is 201 and holds the link in `url`, such as `https://ipso.example.com/invitation#<token>`. Send it to the person yourself: ipso sends no email, because it keeps no address. The answer is the only time the link is shown, because the database keeps the SHA-256 of the token and not the token, so a link that is lost is revoked and made again. The link is a credential until it is used. It lasts seven days, it is used once, and it belongs to this tenant.

The person opens the link and picks a provider. The web app reads the token from the fragment, which no server or proxy sees, removes it from the address, and posts it to `POST /auth/invitation/{id}`. The server checks that the invitation is open, keeps the token in the attempt cookie, and answers where to send the browser. At the end of the sign-in the first login with a valid invitation writes, in one transaction, one person with the name the admin gave, the login of that issuer and subject, the role, the session, and an entry of the action log named `auth.accept_invitation` with the id of the invitation and its role. The invitation is gone, so a second use finds nothing. A person who abandons the sign-in leaves the invitation open until it expires, and a person who is already bound signs in as always and leaves the invitation for the one it was made for.

- `GET /v1/invitations` lists the open ones, without their tokens.
- `DELETE /v1/invitations/{id}` revokes one, so a link that went to the wrong person stops working.
- Only an admin takes these routes ([docs/roles.md](roles.md)), a tenant holds at most 1000 open invitations, and the routes answer 409 when sign-in is not configured, because no one could use the link.

A person who signs in with no invitation and no bound login still gets 403 with the two values:

```json
{"error": "unknown_login", "issuer": "https://accounts.google.com", "subject": "110169484474386276334"}
```

Nothing is written. An operator can still bind a new login to a person who already exists, for example after a Microsoft registration changed every subject, with SQL as the application role:

```sql
BEGIN;
SELECT set_config('ipso.tenant', '<tenant id>', true);
INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ('<tenant id>', '<principal id>', '<issuer>', '<subject>');
COMMIT;
```

A login of an agent cannot start a browser session.

## What a session is

- `GET /auth/providers` lists the providers the server is configured with, as `{"providers":[{"id":"dex","kind":"oidc"}]}`, so the sign-in page of the web app can link to each. It needs no session, names no issuer, client id or secret, and has a rate limit of its own, so reading it never spends the bucket of the callbacks.
- `GET /auth/login/{id}` sends the browser to the provider and keeps the state of the attempt in the cookie `__Host-ipso-login` for ten minutes.
- `POST /auth/invitation/{id}` starts the same sign-in for a person who came with an invitation. It takes `{"token":"..."}`, needs no session, refuses a request from another site, and has a rate limit of its own. It answers 200 with `{"location":"..."}`, the address of the provider, and sets the same cookie with the token in it. A token that is not open is 403 `unknown_invitation` and sets no cookie.
- `GET /auth/callback/{id}` finishes it, clears that cookie on every outcome, and answers 303 to `/` with the cookie `__Host-ipso-session`. A refusal whose `Accept` prefers `text/html` is 303 to `/signin` with the code in the fragment, and every other client still gets the JSON code below.
- `POST /auth/logout` ends the session and clears the cookie. It is a POST, and a request from another site is refused.

The session cookie holds 32 random bytes and the database keeps their SHA-256, so a read of the table is not a session. It is HttpOnly, Secure, SameSite=Strict, and `Path=/`, and the session ends 8 hours after sign-in. Every sign-in mints a new token and ends the session the browser held when the sign-in began. A request that could change state and comes from another origin is refused with 403 before the cookie is looked up. Each process keeps a session it has found for a minute, so a logout on another process takes up to a minute to reach this one.

A session belongs to the one tenant the process serves, and each tenant process needs its own origin. A person in two tenants signs in at each. Choosing a tenant at sign-in is IPSO-138. If you remove the providers, cookies are ignored at once.

## Limits to know

- Logout does not sign the person out of the provider.
- The cookie is SameSite=Strict, and the redirect to `/` after a sign-in follows a navigation that began at the provider, so a browser may load that first page without the cookie. A page that needs the session on its first request should fetch it from the same origin once loaded, and every such fetch carries the cookie. The web app does that: it loads, then asks.
- Two tabs that start a sign-in at once overwrite each other's state cookie, and the first to return fails. Start again.
- The `__Host-` cookies need https. For development, open exactly the origin in `IPSO_PUBLIC_URL`: `localhost` and `127.0.0.1` are different hosts to a cookie, and Safari does not accept a Secure cookie over plain http.
- A provider that sends keys of its own on the callback is fine. Google adds `scope`, `authuser`, and `prompt`. A `state` or `code` that is repeated is refused.

## When a sign-in fails

A client that does not ask for a page gets a short code, and the log says where it stopped, never what the provider sent. A browser asks for HTML, and `GET /auth/callback/{id}` then answers 303 to `/signin` with that same code in the fragment (`#code=invalid_login`). The fragment is not a request the server sees again. Only `unknown_login` adds `issuer` and `subject`, taken from the verified login. The page reads them, removes the fragment from the address, and says in words what to do. `Cache-Control` stays `no-store`. No answer carries a token or a `return_to`. An empty `Accept`, `*/*`, or JSON ahead of HTML keeps the JSON.

- `invalid_login` (400): the state, the attempt cookie, or the `iss` did not match, the code was refused, or the ID token did not verify. The log line has `reason` or `step`, such as `state`, `exchange: invalid_grant`, or `id_token`. Check the issuer, the client id, the client secret, and that the redirect URI is registered exactly.
- `invalid_request` (400, 415): the start of a sign-in with an invitation did not carry one JSON object `{"token":"..."}` with a content type of `application/json`, or was over 1 KiB.
- `login_refused` (400): the provider sent an error, such as `access_denied`.
- `unknown_login` (403): the person has no invitation and no bound login. Invite them, or bind the issuer and subject in the answer.
- `unknown_invitation` (403): the invitation was used, revoked or has expired, or the link is not whole. The token is never in the answer or the log. Make a new invitation.
- `forbidden` (403): the login belongs to an agent.
- `rate_limited` (429): too many sign-ins or lookups on this process. Wait for `Retry-After`.

## Check a real provider

CI proves the generic OpenID Connect path against Dex and each provider's quirks against fakes, but it holds no real client credentials. After you register an application, check it once:

1. Open `{IPSO_PUBLIC_URL}/auth/login/{id}` in a browser, sign in, and end up on `/`.
2. Open `{IPSO_PUBLIC_URL}/v1/scopes` in the same browser and see 200 with JSON.
3. Sign in with an account you did not bind. A browser ends on the sign-in page, which names the issuer and the subject and starts no session. A client that asks for JSON, or names no `Accept`, still sees 403 `unknown_login` with those two values. Make an invitation, open its link in a private window, sign in with that account, and see the person bound, with the invitation gone.
4. Sign out with `fetch('/auth/logout', {method: 'POST'})` from the console of that origin and see `/v1/scopes` answer 401.

## SAML and SCIM

SAML sign-in and SCIM provisioning are enterprise features ([ADR-0131](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0131-saml-and-scim.md)). This binary does not mount them. A provider of kind `saml` is refused at startup unless the enterprise command registered that kind and a license grants `sso.saml`. When the key is not granted, the process still starts and those routes stay unmounted.
