# Onboard, export, restore and offboard a tenant

`ipso-server tenant` runs the life of a tenant from onboarding to deletion ([ADR-0100](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0100-tenant-lifecycle-and-crypto-shredding.md)). These are operator commands. Each prints a JSON report of counts and table names and never a row.

| Command | Credential | What it does |
| --- | --- | --- |
| `tenant create` | the application role, `IPSO_DATABASE_URL`, and the key encryption key `IPSO_TENANT_KEK` | adds the tenant, its wrapped data key, and optionally its first person and login |
| `tenant export` | the application role, `IPSO_DATABASE_URL` | writes every row of the tenant to an age file |
| `tenant restore` | the migration role, `IPSO_MIGRATE_DATABASE_URL` | reads such a file into a fresh tenant |
| `tenant offboard` | the migration role, `IPSO_MIGRATE_DATABASE_URL` | deletes the tenant, proves it, and records a tombstone |

`create` and `export` refuse to start as a superuser or a role that can bypass row-level security, for a table owner, and when `IPSO_MIGRATE_DATABASE_URL` is set. `restore` and `offboard` refuse a superuser and a `BYPASSRLS` role, because the policies of the migration role would mean nothing to them.

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
- Running it again with the same arguments changes nothing. Different arguments are refused. A tenant that already has a wrapped key must open it with the key encryption key in use, so a wrong key stops here.
- The key encryption key is the base64 of 32 random bytes: `openssl rand -base64 32`. It never reaches the database, only `create` reads it, and the api and the worker never see it. Keep it in the secret store of the deployment, apart from the database and its backups. Until IPSO-64 holds it in a cloud KMS, one key wraps every tenant of the deployment.

## Export

```sh
ipso-server tenant export --tenant <id> --recipient age1... --out acme.age
```

The file is encrypted to the age public keys given with `--recipient` (`age-keygen` makes a pair). It is created with mode 0600, never replaces a file, and is removed when the export fails. The customer opens it with stock tools:

```sh
age --decrypt -i key.txt acme.age | gunzip | jq -c 'select(.table == "registry.scope")'
```

It is one consistent snapshot. The first line is the header with the tenant, the format `ipso-tenant-export/1` and a fingerprint of the schema. Then every row is a line `{"table": ..., "row": {...}}`, and the last line lists the row count and SHA-256 of each table. It holds all of the tenant's rows including the history tables and their transaction time. It leaves out the wrapped data key, the sessions, which hold credential hashes and end on their own, and the tombstone. EDR Markdown files and evidence objects are not part of it yet.

An archive is as sensitive as the database. Anyone who holds a recipient's private key reads it, and anyone with a recipient's public key can write one, so restore only an archive you made or have reason to trust.

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

`--confirm` must be the name of the tenant, so a pasted id alone deletes nothing. In one transaction the command deletes every row of the tenant from every table that has a `tenant_id`, the wrapped data key included, and the River jobs that name the tenant. It counts again, writes the tombstone, and commits. Then, in a new transaction, it looks a second time and exits non-zero if any row is left. A repeat removes what appeared since, such as a job a worker inserted while it was still running.

The tombstone, `tenancy.offboarding`, holds the tenant id, the row and job counts, whether a key was destroyed, and the time. It is the record that the tenant was offboarded, and it outlives the tenant. Nothing deletes it.

### What the deletion covers

Deletion within 30 days is the commitment of section 10 of the specification, and backups expire within 35 days. The live database is clean when the command exits zero. Backups and point-in-time recovery keep the rows until they expire. While the key encryption key is one for the whole deployment, a backup copy of the wrapped data key stays openable until then. Per-tenant keys in a cloud KMS (IPSO-64) end that wait: scheduling the destruction of the tenant's key at offboarding makes every copy of its ciphertext unrecoverable at once.

Today no tenant data is encrypted under the data key yet. The key exists so that the first secret ipso seals needs no backfill and so that offboarding has a key to destroy.
