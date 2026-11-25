//go:build integration

package pgtest

import (
	"database/sql"
	"testing"
)

// The decisions SeedEveryTable writes. Their ids are the same in every tenant it seeds.
const (
	DecisionKeep = "00000000-0000-4000-8000-0000000000d1"
	DecisionFrom = "00000000-0000-4000-8000-0000000000d2"
	DecisionTo   = "00000000-0000-4000-8000-0000000000d3"
)

// SeedEveryTable writes a tenant with at least one row in every table the application role can write
// and that the lifecycle commands treat: the tenant, its wrapped key and its installation binding, scopes and their history,
// decisions and their history, supersession, waivers, premises, proposals, identity, role bindings, sessions, the action
// log, usage, an uploaded verdict, and an export with its part. It runs as the application role under row-level security, so every trigger runs as it
// does in production. The tombstone has no application insert and is not seeded here.
func SeedEveryTable(t testing.TB, app *sql.DB, tenant string) {
	t.Helper()
	ctx := t.Context()
	mustScan := func(query string, args []any, dest ...any) {
		t.Helper()
		if err := Scan(ctx, app, tenant, query, args, dest...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	mustExec := func(query string, args ...any) {
		t.Helper()
		if _, err := Exec(ctx, app, tenant, query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}

	var person, org, payments, labs, repo string
	mustExec(`INSERT INTO tenancy.tenant (tenant_id, name) VALUES ($1::uuid, 'synthetic tenant')`, tenant)
	mustExec(`INSERT INTO tenancy.tenant_key (tenant_id, wrapped_dek) VALUES ($1::uuid, decode(repeat('ab', 60), 'hex'))`, tenant)
	// An installation belongs to one tenant in the whole table, so each seeded tenant gets its own id,
	// derived from the tenant: a fixed id would be taken by the second tenant.
	mustExec(`INSERT INTO tenancy.installation (installation_id, tenant_id) VALUES (1 + abs(hashtextextended($1::text, 0) % 1000000000000), $2::uuid)`, tenant, tenant)
	mustScan(`INSERT INTO identity.principal (tenant_id, kind, name) VALUES ($1::uuid, 'human', 'Ada') RETURNING id`,
		[]any{tenant}, &person)
	mustScan(`INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1::uuid, NULL, 'org', 'acme') RETURNING id`,
		[]any{tenant}, &org)
	mustScan(`INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1::uuid, $2::uuid, 'domain', 'payments') RETURNING id`,
		[]any{tenant, org}, &payments)
	mustScan(`INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1::uuid, $2::uuid, 'domain', 'labs') RETURNING id`,
		[]any{tenant, org}, &labs)
	mustScan(`INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1::uuid, $2::uuid, 'repo', 'acme/payments') RETURNING id`,
		[]any{tenant, payments}, &repo)
	mustExec(`UPDATE registry.scope SET parent_id = $2::uuid WHERE id = $1::uuid`, repo, labs)

	body := `{"premises":[{"id":"tls-version"}]}`
	for _, decision := range []struct{ id, valid string }{
		{DecisionKeep, "[2020-01-01,)"},
		{DecisionFrom, "[2020-01-01,2025-01-01)"},
		{DecisionTo, "[2024-01-01,)"},
	} {
		mustExec(`
			INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
			VALUES ($1::uuid, 1, $2::uuid, $3::jsonb, ARRAY[$4::uuid], $5::text::tstzrange)`,
			decision.id, tenant, body, org, decision.valid)
	}
	mustExec(`UPDATE registry.decision_version SET version = 2 WHERE decision_id = $1::uuid AND tenant_id = $2::uuid`, DecisionKeep, tenant)
	mustExec(`
		INSERT INTO registry.supersession (tenant_id, from_decision, to_decision, effective_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, '2024-06-01')`, tenant, DecisionFrom, DecisionTo)
	mustExec(`
		INSERT INTO registry.grandfather_period (tenant_id, decision_id, valid_period)
		VALUES ($1::uuid, $2::uuid, '[2020-01-01,)')`, tenant, DecisionKeep)
	mustExec(`
		INSERT INTO registry.baseline (tenant_id, decision_id, repo, fingerprints)
		VALUES ($1::uuid, $2::uuid, 'acme/payments', ARRAY[sha256('fp')])`, tenant, DecisionKeep)

	var waiver string
	mustScan(`
		INSERT INTO registry.waiver
			(tenant_id, decision_id, scope_id, reason, approver, approver_id, valid_period, ticket_ref)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'synthetic exception', 'Ada', $4::uuid, '[2020-01-01,2020-02-01)', 'OPS-1')
		RETURNING id`, []any{tenant, DecisionKeep, org, person}, &waiver)
	var notice string
	mustScan(`
		INSERT INTO registry.waiver_notice (tenant_id, waiver_id, days_before, ticket_ref)
		VALUES ($1::uuid, $2::uuid, 0, 'OPS-1')
		RETURNING id`, []any{tenant, waiver}, &notice)
	mustExec(`
		INSERT INTO integrations.chat_destination (tenant_id, connector, url_sealed)
		VALUES ($1::uuid, 'slack', decode(repeat('ab', 29), 'hex'))`, tenant)
	mustExec(`
		INSERT INTO integrations.chat_delivery (tenant_id, connector, kind, subject_id)
		VALUES ($1::uuid, 'slack', 'waiver', $2::uuid)`, tenant, notice)

	var evaluation, reason string
	mustScan(`
		INSERT INTO registry.premise_evaluation
			(tenant_id, decision_id, premise_id, result, url, pointer, expected, observed, body_sha256)
		VALUES ($1::uuid, $2::uuid, 'tls-version', 'fail', 'https://example.com/status', '', '1'::jsonb, '0'::jsonb, sha256('body'))
		RETURNING id`, []any{tenant, DecisionKeep}, &evaluation)
	mustScan(`
		INSERT INTO registry.premise_reason (tenant_id, decision_id, premise_id, evaluation_id)
		VALUES ($1::uuid, $2::uuid, 'tls-version', $3::uuid)
		RETURNING id`, []any{tenant, DecisionKeep, evaluation}, &reason)
	mustExec(`
		INSERT INTO registry.premise_clearance (tenant_id, reason_id, kind)
		VALUES ($1::uuid, $2::uuid, 'human')`, tenant, reason)
	mustExec(`
		INSERT INTO registry.premise_host_allow (tenant_id, host, allowed)
		VALUES ($1::uuid, 'example.com', true)`, tenant)

	var proposal string
	mustScan(`
		INSERT INTO proposals.proposal
			(tenant_id, payload, confidence, model_id, prompt_version, repo, pr_number, external_id, source_url, source_sha256, candidate_index)
		VALUES ($1::uuid, '{"title":"Use Postgres"}', 0.8, 'm', 'p', 'acme/payments', 8, 'comment1',
		        'https://github.com/acme/payments/pull/8', decode(repeat('ab', 32), 'hex'), 0)
		RETURNING id`, []any{tenant}, &proposal)
	mustExec(`
		INSERT INTO proposals.approval (tenant_id, proposal_id, approver_id, outcome, decision_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'approved', $4::uuid)`, tenant, proposal, person, DecisionKeep)
	var agentProposal string
	mustScan(`
		INSERT INTO proposals.agent_proposal (tenant_id, principal_id, payload)
		VALUES ($1::uuid, $2::uuid, '{"title":"Pin versions"}')
		RETURNING id`, []any{tenant, person}, &agentProposal)
	mustExec(`
		INSERT INTO proposals.agent_approval (tenant_id, proposal_id, approver_id, outcome, decision_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'approved', $4::uuid)`, tenant, agentProposal, person, DecisionTo)
	mustExec(`
		INSERT INTO integrations.tracker_binding (tenant_id, connector, external_account, token_sealed, webhook_sealed)
		VALUES ($1::uuid, 'jira', 'acct-' || $1::text, decode(repeat('ab', 29), 'hex'), decode(repeat('cd', 29), 'hex'))`, tenant)
	var trackerProposal string
	mustScan(`
		INSERT INTO proposals.tracker_proposal
			(tenant_id, connector, payload, confidence, model_id, prompt_version, external_id, source_url, source_sha256, candidate_index)
		VALUES ($1::uuid, 'jira', '{"title":"Use Postgres","statement":"Use Postgres for new services","rationale":"the ticket"}',
		        0.8, 'm', 'p', 'OPS-1', 'https://acme.atlassian.net/browse/OPS-1', decode(repeat('ab', 32), 'hex'), 0)
		RETURNING id`, []any{tenant}, &trackerProposal)
	mustExec(`
		INSERT INTO proposals.tracker_approval (tenant_id, proposal_id, approver_id, outcome, decision_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'approved', $4::uuid)`, tenant, trackerProposal, person, DecisionFrom)
	mustExec(`
		INSERT INTO integrations.tracker_link (tenant_id, connector, external_id, url, kind, proposal_id, status)
		VALUES ($1::uuid, 'jira', 'OPS-1', 'https://acme.atlassian.net/browse/OPS-1', 'decision', $2::uuid, 'open')`, tenant, trackerProposal)
	mustExec(`
		INSERT INTO integrations.tracker_link (tenant_id, connector, external_id, url, kind, waiver_id, status)
		VALUES ($1::uuid, 'jira', 'OPS-2', 'https://acme.atlassian.net/browse/OPS-2', 'waiver', $2::uuid, 'open')`, tenant, waiver)
	mustExec(`
		INSERT INTO proposals.check_proposal
			(tenant_id, decision_id, decision_version, spec, rego, rego_sha256, fixtures, fixtures_total, fixtures_passed, repaired, model_id, prompt_version)
		VALUES ($1::uuid, $2::uuid, 1, '{}'::jsonb, 'package p', sha256(convert_to('package p', 'UTF8')),
		        '[{},{}]'::jsonb, 2, 2, false, 'm', 'v1')`, tenant, DecisionKeep)
	mustExec(`
		INSERT INTO proposals.check_approval (tenant_id, proposal_id, approver_id, outcome)
		SELECT tenant_id, id, $2::uuid, 'rejected' FROM proposals.check_proposal WHERE tenant_id = $1::uuid`, tenant, person)
	mustExec(`
		INSERT INTO identity.login (tenant_id, principal_id, issuer, subject)
		VALUES ($1::uuid, $2::uuid, 'https://idp.example.test', 'subject-1')`, tenant, person)
	mustExec(`
		INSERT INTO identity.role_binding (tenant_id, principal_id, role, scope_id)
		VALUES ($1::uuid, $2::uuid, 'admin', NULL), ($1::uuid, $2::uuid, 'approver', $3::uuid)`, tenant, person, repo)
	mustExec(`
		INSERT INTO identity.session (tenant_id, login_id, token_sha256)
		SELECT tenant_id, id, sha256(convert_to('seeded session', 'UTF8')) FROM identity.login`)
	mustExec(`
		INSERT INTO identity.cli_session (tenant_id, login_id, token_sha256)
		SELECT tenant_id, id, sha256(convert_to('seeded cli session', 'UTF8')) FROM identity.login`)
	var humanProposal string
	mustScan(`
		INSERT INTO proposals.human_proposal (tenant_id, principal_id, payload)
		VALUES ($1::uuid, $2::uuid, '{"title":"Deny default egress","statement":"Deny 0.0.0.0/0 egress"}')
		RETURNING id`, []any{tenant, person}, &humanProposal)
	mustExec(`
		INSERT INTO proposals.human_approval (tenant_id, proposal_id, approver_id, outcome)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'rejected')`, tenant, humanProposal, person)
	mustExec(`
		INSERT INTO llm.tenant_policy (tenant_id, allow_authoring_assist, allow_check_eval)
		VALUES ($1::uuid, false, false)`, tenant)
	mustExec(`
		INSERT INTO verification.agent_pin (tenant_id, name, repo, env, pin_sha256, public_key_der)
		VALUES ($1::uuid, 'prod-agent', 'acme/payments', 'prod', sha256(convert_to('pin-' || $1::text, 'UTF8')), decode(repeat('30', 32), 'hex'))`, tenant)
	mustExec(`
		INSERT INTO verification.freshness_policy (tenant_id, env, max_age_days)
		VALUES ($1::uuid, 'prod', 7)`, tenant)
	mustExec(`
		INSERT INTO identity.invitation (tenant_id, token_sha256, name, role, created_by)
		VALUES ($1::uuid, sha256(convert_to('seeded invitation', 'UTF8')), 'Invited', 'viewer', $2::uuid)`, tenant, person)
	mustExec(`
		INSERT INTO identity.scim_user (tenant_id, principal_id, external_id, user_name)
		VALUES ($1::uuid, $2::uuid, 'subject-1', 'ada@example.test')`, tenant, person)
	mustExec(`
		INSERT INTO identity.scim_token (tenant_id, token_sha256)
		VALUES ($1::uuid, sha256(convert_to('seeded scim token', 'UTF8')))`, tenant)
	mustExec(`
		INSERT INTO identity.scim_group (tenant_id, group_ref)
		VALUES ($1::uuid, 'engineering')`, tenant)
	mustExec(`
		INSERT INTO identity.scim_membership (tenant_id, group_id, principal_id)
		SELECT $1::uuid, id, $2::uuid FROM identity.scim_group WHERE tenant_id = $1::uuid`, tenant, person)
	mustExec(`
		INSERT INTO identity.idp_group_role (tenant_id, group_ref, role)
		VALUES ($1::uuid, 'engineering', 'viewer')`, tenant)
	mustExec(`
		INSERT INTO identity.idp_group_owner (tenant_id, group_ref, owner_ref)
		VALUES ($1::uuid, 'engineering', 'team:platform')`, tenant)
	mustExec(`
		INSERT INTO identity.principal_owner (tenant_id, principal_id, owner_ref)
		VALUES ($1::uuid, $2::uuid, 'team:platform')`, tenant, person)
	mustExec(`
		INSERT INTO identity.action_log (tenant_id, principal_id, responsible_id, action, subject)
		VALUES ($1::uuid, $2::uuid, $2::uuid, 'api.read', 'registry')`, tenant, person)
	mustExec(`INSERT INTO llm.usage (tenant_id, month, tokens) VALUES ($1::uuid, '2026-01-01', 1)`, tenant)

	var upload string
	mustScan(`
		INSERT INTO verification.upload
			(tenant_id, installation_id, repository_id, repo, run_id, run_attempt, sha, ref, event_name, workflow_ref,
			 check_name, env, ipso_version, evaluated_at, build_sha256, sarif_sha256, evidence, content_sha256)
		VALUES ($1::uuid, 1, 1, 'acme/payments', 1, 1, repeat('ab', 20), 'refs/heads/main', 'push',
		        'acme/payments/.github/workflows/ci.yml@refs/heads/main', 'plan', 'prod', '0.5.0', '2026-01-01T00:00:00Z',
		        sha256('build'), sha256('sarif'), jsonb_build_object('plan_sha256', encode(sha256('plan'), 'hex')), sha256('upload'))
		RETURNING id`, []any{tenant}, &upload)
	mustExec(`
		INSERT INTO verification.verdict (tenant_id, upload_id, decision_id, slug, check_index, mode, result, violations, fingerprints)
		VALUES ($1::uuid, $2::uuid, '01M5QJ0V9EVXKR4C89XNBNT5GG', 'use-tls', 0, 'block', 'fail', 2,
		        ARRAY[sha256('violation a'), sha256('violation b')])`, tenant, upload)

	// A finished export an admin asked for, with its one part (ADR-0111). It finished an hour ago, so a new
	// request is past the cooldown and replaces it.
	var export string
	mustScan(`
		INSERT INTO tenancy.export (tenant_id, requested_by, recipient, state, created_at, finished_at, expires_at, bytes, parts, sha256)
		VALUES ($1::uuid, $2::uuid, 'age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p', 'ready',
		        now() - interval '2 hours', now() - interval '1 hour', now() + interval '1 day', 4, 1, sha256('data'::bytea))
		RETURNING id`, []any{tenant, person}, &export)
	mustExec(`
		INSERT INTO tenancy.export_part (tenant_id, export_id, seq, data)
		VALUES ($1::uuid, $2::uuid, 0, 'data'::bytea)`, tenant, export)
}
