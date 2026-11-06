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

## Bind a person

A sign-in becomes a session only for a login the tenant has bound to a person (ADR-0093). The flow creates nobody, so a person who signs in for the first time and is not bound gets 403 with the two values to bind:

```json
{"error": "unknown_login", "issuer": "https://accounts.google.com", "subject": "110169484474386276334"}
```

Nothing is written. An operator binds the person with SQL as the application role, the way the seed of the local stack does:

```sql
BEGIN;
SELECT set_config('ipso.tenant', '<tenant id>', true);
INSERT INTO identity.principal (tenant_id, kind, name) VALUES ('<tenant id>', 'human', 'Ada') RETURNING id;
INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ('<tenant id>', '<principal id>', '<issuer>', '<subject>');
COMMIT;
```

A login of an agent cannot start a browser session. The route that binds a person without SQL is IPSO-137, and it waits for the role policy of IPSO-66.

## What a session is

- `GET /auth/login/{id}` sends the browser to the provider and keeps the state of the attempt in the cookie `__Host-ipso-login` for ten minutes.
- `GET /auth/callback/{id}` finishes it, clears that cookie on every outcome, and answers 303 to `/` with the cookie `__Host-ipso-session`.
- `POST /auth/logout` ends the session and clears the cookie. It is a POST, and a request from another site is refused.

The session cookie holds 32 random bytes and the database keeps their SHA-256, so a read of the table is not a session. It is HttpOnly, Secure, SameSite=Strict, and `Path=/`, and the session ends 8 hours after sign-in. Every sign-in mints a new token and ends the session the browser held when the sign-in began. A request that could change state and comes from another origin is refused with 403 before the cookie is looked up. Each process keeps a session it has found for a minute, so a logout on another process takes up to a minute to reach this one.

A session belongs to the one tenant the process serves, and each tenant process needs its own origin. A person in two tenants signs in at each. Choosing a tenant at sign-in is IPSO-138. If you remove the providers, cookies are ignored at once.

## Limits to know

- Logout does not sign the person out of the provider.
- The cookie is SameSite=Strict, and the redirect to `/` after a sign-in follows a navigation that began at the provider, so a browser may load that first page without the cookie. A page that needs the session on its first request should fetch it from the same origin once loaded, and every such fetch carries the cookie.
- Two tabs that start a sign-in at once overwrite each other's state cookie, and the first to return fails. Start again.
- The `__Host-` cookies need https. For development, open exactly the origin in `IPSO_PUBLIC_URL`: `localhost` and `127.0.0.1` are different hosts to a cookie, and Safari does not accept a Secure cookie over plain http.
- A provider that sends keys of its own on the callback is fine. Google adds `scope`, `authuser`, and `prompt`. A `state` or `code` that is repeated is refused.

## When a sign-in fails

The answer is a short code and the log says where it stopped, never what the provider sent.

- `invalid_login` (400): the state, the attempt cookie, or the `iss` did not match, the code was refused, or the ID token did not verify. The log line has `reason` or `step`, such as `state`, `exchange: invalid_grant`, or `id_token`. Check the issuer, the client id, the client secret, and that the redirect URI is registered exactly.
- `login_refused` (400): the provider sent an error, such as `access_denied`.
- `unknown_login` (403): bind the issuer and subject in the answer.
- `forbidden` (403): the login belongs to an agent.
- `rate_limited` (429): too many sign-ins or lookups on this process. Wait for `Retry-After`.

## Check a real provider

CI proves the generic OpenID Connect path against Dex and each provider's quirks against fakes, but it holds no real client credentials. After you register an application, check it once:

1. Open `{IPSO_PUBLIC_URL}/auth/login/{id}` in a browser, sign in, and end up on `/`.
2. Open `{IPSO_PUBLIC_URL}/v1/scopes` in the same browser and see 200 with JSON.
3. Sign in with an account you did not bind and see 403 `unknown_login` and no session.
4. Sign out with `fetch('/auth/logout', {method: 'POST'})` from the console of that origin and see `/v1/scopes` answer 401.
