# The audit log

`identity.action_log` records what a person or an agent did, and since [ADR-0126](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0126-hash-chained-action-log.md) it is a hash chain: every tenant has one chain, the database sets each entry's place in it, and an entry cannot be changed or removed without the chain showing it. An auditor or an admin reads it as JSON lines, and an operator checks it with a command.

## What is in the log

| Entry | Written by | Subject |
| --- | --- | --- |
| `api.<operation>` for every write a person makes and for starting and downloading an export | the write, in the same transaction | the ids it wrote, never a reason, a ticket or a body |
| `api.<operation>` for every call an agent makes | the guard, before the call runs | the request target, cut to 200 characters |
| `decisions.applicable`, `decisions.get`, `checks.evaluate`, `decisions.propose` | the remote MCP handler, before the tool runs | the repository, the reference or the title, cut to 200 characters |

A write that cannot be logged does not run, and an entry never outlives a write that failed. A person's reads, a refused call, a CI verdict upload, the worker's jobs, a sign-in and the operator commands on a tenant are not in the log. The commands are a follow-up of IPSO-68, because an entry needs a principal and a command has none.

## The chain

Each entry carries `seq`, its place in the chain of its tenant, from 1 without a gap, `prev_hash`, the hash of the entry before it (32 zero bytes for the first), and `hash`. The BEFORE INSERT trigger `identity.action_log_stamp` sets all three and the time of the entry, whatever the caller sent. It takes a lock per tenant that is held until the transaction ends, so entries commit in the order of their positions and two writers never read the same head. The trigger refuses a transaction that is not READ COMMITTED, and `UNIQUE (tenant_id, seq)` is the second wall: a fork fails and does not commit.

The hash is the SHA-256 of nine lines joined by a line feed, in UTF-8: the format name `ipso-audit-log/1`, the previous hash as 64 lowercase hex digits, `seq` in decimal, the entry id, the time, the principal, the person responsible, the action and the subject. Ids are lowercase and the time is UTC with six digits, as in `2026-11-15T08:30:00.123456Z`. The tenant id is not in it, so a chain still verifies after a restore into another tenant. The text has no line feed inside a field, because the action grammar and the subject check forbid control characters.

A vector to check an implementation against, the first entry of a chain:

| Field | Value |
| --- | --- |
| `prev` | 64 zeros |
| `seq` | `1` |
| `id` | `018f3e6a-1c2b-7d4e-8f50-123456789abc` |
| `at` | `2026-11-15T08:30:00.123456Z` |
| `principal` | `11111111-1111-4111-8111-111111111111` |
| `responsible` | `22222222-2222-4222-8222-222222222222` |
| `action` | `api.record_waiver` |
| `subject` | `waiver w1 of "use-tls" \ é 日本` |
| `hash` | `3d0a1548f7077ac48f360148a5ce92e0dc57c63d8ac070b494079962b74ee2d2` |

## The log is append-only

`ipso_app` can select and insert and nothing else. Two triggers, `action_log_append_only` and `action_log_no_truncate`, refuse update, delete and truncate for the owner of the table and for a superuser too. They are ordinary triggers, so the restore and offboard commands, which run with `session_replication_role = replica` ([ADR-0100](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0100-tenant-lifecycle-and-crypto-shredding.md)), still work. Whoever can turn triggers off can still rewrite the table, which is why the chain is checked.

## Reading it: `GET /v1/audit-log`

The route needs the `audit.read` action, which `auditor` and `admin` hold and an agent never does ([docs/roles.md](roles.md)). It takes one query key, `after`, the `seq` of the last line the reader kept, and defaults to 0. The answer is `200 application/jsonl` with the lines whose `seq` is above `after`, oldest first, at most 1000 and about 1 MiB, each a JSON object followed by a newline. An empty body means nothing is new. A reader continues from the `seq` of its last line.

```json
{"format":"ipso-audit-log/1","seq":1,"id":"018f3e6a-1c2b-7d4e-8f50-123456789abc","at":"2026-11-15T08:30:00.123456Z","principal":"11111111-1111-4111-8111-111111111111","responsible":"22222222-2222-4222-8222-222222222222","action":"api.record_waiver","subject":"waiver w1","prev":"0000000000000000000000000000000000000000000000000000000000000000","hash":"..."}
```

A line holds exactly the fields the hash covers, so a reader checks each hash from the line alone, and that a page continues the one before it: the `prev` of its first line is the `hash` of the last line it kept. A position is assigned under a lock that is held to the commit, so a reader that continues from the last `seq` never skips an entry that commits later. Lines name principals by id and carry no name and no email. Reading the log writes no entry, so a poller does not feed on its own reads. The route is in every edition.

## Checking it: `ipso-server audit-log verify`

```sh
ipso-server audit-log verify --tenant <id>
```

The command runs as the application role from `IPSO_DATABASE_URL`, reads the whole chain of the tenant in one snapshot, and prints a JSON report with `entries`, `head_seq`, `head_hash` and `intact`. When the chain does not hold it exits 1 and `break` names the first entry that fails: `gap` for a missing or reordered position, `prev` for an entry that does not carry the hash of the one before it, `hash` for an entry whose hash is not the hash of its fields.

A chain proves itself from its first entry on. It cannot show that entries after the head were removed, or that the whole tail was rewritten with fresh hashes, by someone who can write the table. Only an older head kept elsewhere shows that, which is what the SIEM that polls the route holds, and what the offboarding tombstone keeps for a tenant that is gone.

## Retention and offboarding

Entries are never pruned while the tenant exists, which meets the retention of section 13 of the specification: 1 year for Team and 7 years for Enterprise. Offboarding deletes the log with the tenant's other rows, because deletion within 30 days is the commitment of section 10. The tombstone `tenancy.offboarding` keeps the head, `log_seq` and `log_hash`, read in the same transaction before the delete, so a customer who kept a copy of the log can show that it was complete and unaltered after the tenant is gone. Both are empty when the log was empty and for a tombstone written before migration 00034.

An export archive carries the log with its chain, and a restore keeps every position and hash. An archive made before migration 00034 has another table shape, so a restore refuses it.
