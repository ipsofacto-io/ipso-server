# Run the control plane on a laptop

One Compose file starts the control plane with everything it needs: PostgreSQL 18, the migrations, a seeded tenant, and Dex as the OIDC provider. It is for trying the API and for developing against it. It is not a supported install: the Helm chart and the bundle of IPSO-77 are.

You need Docker with Compose v2.

```sh
cp .env.example .env
docker compose up --build
```

The values in `.env.example` are test-only, and they are the only place a credential lives. Copy the file to `.env` to change one. Nothing is published except two loopback ports: the front on `127.0.0.1:8080` and Dex on `127.0.0.1:5556`.

## What starts

- `postgres`: PostgreSQL 18, with the two roles of the install in the README: `ipso_migrate` owns the schema, and `ipso_app` owns nothing and cannot bypass row-level security.
- `certs`: makes a throwaway CA and a certificate for Dex, because the API only accepts an https issuer. The CA key is deleted after signing.
- `dex`: the OIDC provider, with the clients `ipso-api` and `other-app` and one test user.
- `migrate`: applies the migrations as the migration role, then exits. It is the only service that holds that credential.
- `seed`: writes the tenant row, one person, and the login that binds the test user's subject to that person, as the application role. It is safe to run again.
- `api`: `ipso-server --role=api` as the application role. It refuses to start as a role that owns a table or can bypass row-level security, for a tenant with no row, and when it holds the migration credential.
- `front`: nginx, the only way in. It allows each client address 20 requests a second with a burst of 40, before a request reaches the API, so a request with no valid token is limited too.

There is no worker yet. The job runtime is chosen by IPSO-132, and the `worker` role is added to this file when it exists.

## Call the API

The API answers a token that Dex minted for the `ipso-api` client, and refuses every other. Ask Dex for one with the password grant. The CA is in the `certs` volume:

```sh
docker compose cp certs:/certs/ca.pem ./ca.pem
set -a; . ./.env; set +a
TOKEN=$(curl --silent --cacert ca.pem https://localhost:5556/dex/token \
  --data grant_type=password --data scope=openid \
  --data username="$IPSO_DEX_USER" --data-urlencode password="$IPSO_DEX_PASSWORD" \
  --data client_id=ipso-api --data-urlencode client_secret="$IPSO_API_CLIENT_SECRET" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
curl --silent -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/v1/scopes
```

`GET /healthz` needs no token. The routes are in [api/openapi.yaml](../api/openapi.yaml). The registry is empty, and no route writes yet (IPSO-134).

A token minted for `other-app` is refused with 401, and a valid token whose subject the tenant never bound is refused with 403. The tenant is never read from the request: a `tenant` key in the query is 400.

## Clean up

```sh
docker compose down --volumes
```

This removes the database and the certificates. The next `up` makes new ones.

## How it is tested

`ci / compose` starts this stack from a clean checkout with `.env.example`, runs `deploy/compose/smoke_test.go` against it, and checks that `ipso-server --role=api` exits with "refusing to start" when it is given the migration role. The images are pinned by digest, so a run never picks up a different build.

## Remote MCP

The stack does not mount the remote MCP handler. It needs an authorization server that offers PKCE with S256 and Client ID Metadata Documents, and Dex offers no Client ID Metadata Documents. A deployment with such a server sets `IPSO_MCP_ISSUER` and `IPSO_MCP_RESOURCE_URL` on the `api` service, and the handler is mounted with its own audience.
