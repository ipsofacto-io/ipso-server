# Onboard, export, restore and offboard a tenant

`ipso-server tenant` runs the life of a tenant from onboarding to deletion ([ADR-0100](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0100-tenant-lifecycle-and-crypto-shredding.md)). These are operator commands. Each prints a JSON report of counts and table names and never a row. An admin of a tenant can also export it through the API, without an operator: see [Export through the API](#export-through-the-api).

| Command | Credential | What it does |
| --- | --- | --- |
| `tenant create` | the application role, `IPSO_DATABASE_URL`, and the key encryption key `IPSO_TENANT_KEK` | adds the tenant, its wrapped data key, and optionally its first person and login |
| `tenant export` | the application role, `IPSO_DATABASE_URL` | writes every row of the tenant to an age file |
| `tenant restore` | the migration role, `IPSO_MIGRATE_DATABASE_URL` | reads such a file into a fresh tenant |
| `tenant offboard` | the migration role, `IPSO_MIGRATE_DATABASE_URL` | deletes the tenant, proves it, and records a tombstone |
| `tenant bind-installation` | the application role, `IPSO_DATABASE_URL`, and the GitHub App `IPSO_GITHUB_APP_ID` and `IPSO_GITHUB_APP_PRIVATE_KEY` | says that a GitHub App installation belongs to the tenant |

`create`, `export` and `bind-installation` refuse to start as a superuser or a role that can bypass row-level security, for a table owner, and when `IPSO_MIGRATE_DATABASE_URL` is set. `restore` and `offboard` refuse a superuser and a `BYPASSRLS` role, because the policies of the migration role would mean nothing to them.

## Onboard

```sh
export IPSO_DATABASE_URL=postgres://ipso_app:...@db.example/ipso
export IPSO_TENANT_KEK="$(cat /path/to/kek.b64)"
ipso-server tenant create --tenant 0190a0a0-0000-7000-8000-000000000001 --name acme \
  --person 0190a0a0-0000-7000-8000-0000000000a1 --person-name "Ada" \
  --issuer https://accounts.google.com --subject 110169484474386276334
```

- The tenant id is chosen by the operator, and a process serves it with `IPSO_TENANT_ID`. An id that was offboarded is refused for good.
- The person is optional, and the four `--person` flags are given together or not at all. A tenant that will receive a restore is created without one.
- The person becomes the tenant's first `admin`, over the whole tenant, so someone can bind the others ([docs/roles.md](roles.md)). Running it again binds the admin only while the tenant has no admin, so it adds the role to a tenant created before roles existed and a deliberate revoke is kept while another admin remains.
- Running it again with the same arguments changes nothing. Different arguments are refused. A tenant that already has a wrapped key must open it with the key encryption key in use, so a wrong key stops here.
- The key encryption key is the base64 of 32 random bytes: `openssl rand -base64 32`. It never reaches the database, only `create` reads it, and the api and the worker never see it. Keep it in the secret store of the deployment, apart from the database and its backups. Until IPSO-64 holds it in a cloud KMS, one key wraps every tenant of the deployment.

## Bind a GitHub App installation

```sh
ipso-server tenant bind-installation --tenant <id> --installation 12345678 --account acme
```

The GitHub App service takes the tenant of a delivery from this binding and never from the payload ([ADR-0101](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0101-installation-tenant-mapping.md)), so an installation must be bound before the App does anything for it. The command asks GitHub, as the App, which account the installation is on, and binds nothing unless the installation is this App's and its account is the login given with `--account`. [github-app.md](github-app.md) shows where to find the installation id.

- An installation belongs to one tenant. A second tenant's bind is refused, and the error does not name the owner. Binding the same pair again changes nothing, and a tenant may hold several installations.
- The tenant must exist and must not have been offboarded.
- The application role can write a binding once and cannot change or delete it. Offboarding removes a tenant's bindings, which frees the installation for another tenant.

## Export

```sh
ipso-server tenant export --tenant <id> --recipient age1... --out acme.age
```

The file is encrypted to the age public keys given with `--recipient` (`age-keygen` makes a pair). It is created with mode 0600, never replaces a file, and is removed when the export fails. The customer opens it with stock tools:

```sh
age --decrypt -i key.txt acme.age | gunzip | jq -c 'select(.table == "registry.scope")'
```

It is one consistent snapshot. The first line is the header with the tenant, the format `ipso-tenant-export/2` and a fingerprint of the schema. Then every row is a line `{"table": ..., "row": {...}}`. After the rows come the decisions as EDR Markdown files, one line `{"file": ..., "text": ...}` for each version of each decision, and the last line lists the row count and SHA-256 of each table and the count and SHA-256 of the file lines. It holds all of the tenant's rows including the history tables and their transaction time. It leaves out the wrapped data key, the sessions, which hold credential hashes and end on their own, the tombstone, and the installation bindings, which are unique across tenants. After a restore, bind the installation to the new tenant if it should receive the App's deliveries. Evidence objects are not part of it yet.

The decisions can be read without ipso. A file is named `edr/current/<decision id>/v<version>_valid-<time>_known-<time>.md` for a version in force and `edr/history/...` for a version that was replaced, and each one passes `ipso check`. A field that a stored decision lacks is filled with a default and the file says `inferred: true`. This writes them to the current directory:

```sh
age --decrypt -i key.txt acme.age | gunzip | jq -r 'select(.file | strings | startswith("edr/") and (contains("..") | not)) | [.file, (.text | @base64)] | @tsv' |
  while IFS=$(printf '\t') read -r name text; do mkdir -p "$(dirname "$name")"; printf "%s" "$text" | base64 -d > "$name"; done
```

A restore ignores the files and restores from the rows. Format 1 archives, made before the files were added, still restore.

An archive is as sensitive as the database. Anyone who holds a recipient's private key reads it, and anyone with a recipient's public key can write one, so restore only an archive you made or have reason to trust.

## Export through the API

An admin of the tenant who is a person can ask for the same export ([ADR-0111](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0111-tenant-export-through-the-api.md)). The worker makes the archive, so `--role=worker` has to be running for the tenant. The admin gives one age public key, and the archive is encrypted to it and to nobody else.

```sh
curl -sS -X POST "$IPSO/v1/exports" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"recipient":"age1..."}'
```

The answer is 202 with the export in the state `pending`. The worker finds the request within a minute, so read it until it is `ready`, and then download it:

```sh
curl -sS "$IPSO/v1/exports/$ID" -H "Authorization: Bearer $TOKEN"
curl -sS -o acme.age "$IPSO/v1/exports/$ID/archive" -H "Authorization: Bearer $TOKEN"
```

`GET /v1/exports/current` gives the export the tenant holds, in any state, or 404 when there is none ([ADR-0115](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0115-web-app-export-screen.md)), so an admin finds the export again after the 409 of a second request. The web app has the same flow at `/export` ([web-app.md](web-app.md)), so the export needs no `curl`.

The file is the one `tenant export` writes, so the `age --decrypt` command above opens it and `tenant restore` reads it. The API refuses a recipient that is not exactly one native or hybrid public key, with 400, and never quotes it.

A tenant holds one current export. While one is pending or running a new request is 409. Ten minutes after the last export finished or failed a new request is accepted, and sooner it is 429 with a `Retry-After`. A new request replaces a finished one: the old id is a 404 at once, and its parts are kept for half an hour so that a download in flight can end. An export can be downloaded for 24 hours and is then deleted, with the same half hour of grace. A process sends two archives at once and answers a third with 429 and a `Retry-After`. A tenant whose archive would pass 1 GiB gets an export in the state `failed`: use the operator command for it. The worker's log says why any export failed, and the admin can ask again.

The archive waits in PostgreSQL, encrypted to the key the admin gave, so a copy of the database holds no export in the clear. Each request and each download is logged with the person's id in `identity.action_log`, which the audit log of IPSO-68 builds on. A reverse proxy in front of the API must let a download run for as long as the client takes and must not spool it to disk: the Compose front sets `proxy_max_temp_file_size 0`.

## Restore

```sh
ipso-server tenant create --tenant <new id> --name acme-restored
ipso-server tenant restore --tenant <new id> --identity key.txt --in acme.age
```

The target must exist and hold no rows but its own tenant row and key, and the schema of the archive must be this database's. The identity file must not be readable by others. One transaction writes the rows with their ids and their transaction time, and it commits only when the archive matches its trailer and no foreign key is left without its row. Any failure writes nothing. Every row takes the target's tenant id, whatever the archive says.

Restore runs as the migration role with triggers and foreign-key triggers off for its own transaction. That needs one grant from the administrator who installed the database, once ([README](../README.md#database-schema)):

```sql
GRANT SET ON PARAMETER session_replication_role TO ipso_migrate;
```

## Offboard

1. Stop the api and the worker of the tenant, and remove its entries from the LLM gateway configuration.
2. Export the tenant if the customer asked for it, and give them the file.
3. Run it:

```sh
ipso-server tenant offboard --tenant <id> --confirm acme
```

`--confirm` must be the name of the tenant, so a pasted id alone deletes nothing. In one transaction the command deletes every row of the tenant from every table that has a `tenant_id`, the wrapped data key and the installation bindings included, and the River jobs that name the tenant. It counts again, writes the tombstone, and commits. Then, in a new transaction, it looks a second time and exits non-zero if any row is left. A repeat removes what appeared since, such as a job a worker inserted while it was still running.

The tombstone, `tenancy.offboarding`, holds the tenant id, the row and job counts, whether a key was destroyed, and the time. It is the record that the tenant was offboarded, and it outlives the tenant. Nothing deletes it.

### What the deletion covers

Deletion within 30 days is the commitment of section 10 of the specification, and backups expire within 35 days. The live database is clean when the command exits zero. Backups and point-in-time recovery keep the rows until they expire. While the key encryption key is one for the whole deployment, a backup copy of the wrapped data key stays openable until then. Per-tenant keys in a cloud KMS (IPSO-64) end that wait: scheduling the destruction of the tenant's key at offboarding makes every copy of its ciphertext unrecoverable at once.

Today no tenant data is encrypted under the data key yet. The key exists so that the first secret ipso seals needs no backfill and so that offboarding has a key to destroy.
