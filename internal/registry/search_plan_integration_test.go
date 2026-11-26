//go:build integration

package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

// legacyKeywordRead is the SearchDecisions SQL before ADR-0169: neither @@ nor ILIKE is leakproof,
// so under row-level security no index is usable and it scans every row of the tenant. Kept so the
// test proves its plan check rejects a regression to it.
const legacyKeywordRead = `
SELECT DISTINCT ON (d.decision_id) d.decision_id, d.version, d.body
FROM registry.decision_version_all d
WHERE d.tenant_id = ipso.current_tenant()
  AND d.valid_period @> $1::timestamptz
  AND d.sys_period @> $2::timestamptz
  AND ($3::uuid IS NULL OR d.decision_id < $3::uuid)
  AND (
      (
          NOT (coalesce(d.body->'tags', '[]'::jsonb) ? 'sensitive')
          AND NOT coalesce((d.body->>'sensitive')::boolean, false)
          AND (
              to_tsvector('simple',
                  coalesce(d.body->>'title', '') || ' ' ||
                  coalesce(d.body->>'slug', '') || ' ' ||
                  coalesce(d.body->>'statement', '')) @@ plainto_tsquery('simple', $5)
              OR coalesce(d.body->>'title', '') ILIKE '%' || $6 || '%' ESCAPE '\'
          )
      )
      OR coalesce(d.body->>'slug', '') ILIKE '%' || $6 || '%' ESCAPE '\'
  )
ORDER BY d.decision_id DESC, d.version DESC
LIMIT $4`

// searchPlanProblems reports what is wrong with the plan of a keyword search read under RLS. The
// read is right when decision_search_term_pkey is scanned on term, every decision version table is
// reached by an index condition on decision_id, and the tenant's non-matching rows are not removed
// by filter.
func searchPlanProblems(root planNode, tenantRows int) []string {
	var problems []string
	lookup := false
	removed := 0.0
	root.walk(func(n planNode) {
		if n.Index == "decision_search_term_pkey" && strings.Contains(n.IndexCond, "term") {
			lookup = true
		}
		if n.Relation != "decision_version" && n.Relation != "decision_version_history" {
			return
		}
		removed += n.Removed * max(n.Loops, 1)
		switch n.NodeType {
		case "Index Scan", "Index Only Scan":
			if !strings.Contains(n.IndexCond, "decision_id") {
				problems = append(problems, fmt.Sprintf("%s is read by %s with no condition on decision_id: %q", n.Relation, n.NodeType, n.IndexCond))
			}
		case "Bitmap Heap Scan":
			if !strings.Contains(n.RecheckCond, "decision_id") {
				problems = append(problems, fmt.Sprintf("%s is read by a bitmap scan with no condition on decision_id: %q", n.Relation, n.RecheckCond))
			}
		default:
			problems = append(problems, fmt.Sprintf("%s is read by %s", n.Relation, n.NodeType))
		}
	})
	if !lookup {
		problems = append(problems, "no node reads decision_search_term_pkey by term")
	}
	if limit := float64(tenantRows) / 10; removed > limit {
		problems = append(problems, fmt.Sprintf("the version rows removed by filter are %.0f of %d, over %.0f", removed, tenantRows, limit))
	}
	return problems
}

func explainAnalyzeBuffers(ctx context.Context, tx *sql.Tx, stmt string, args ...any) (planNode, float64, float64, error) {
	var raw []byte
	if err := tx.QueryRowContext(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+stmt, args...).Scan(&raw); err != nil {
		return planNode{}, 0, 0, err
	}
	var plans []struct {
		Plan          planNode `json:"Plan"`
		ExecutionTime float64  `json:"Execution Time"`
	}
	if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
		return planNode{}, 0, 0, fmt.Errorf("unreadable plan: %v", err)
	}
	var buffers struct {
		Plan struct {
			SharedHit  float64 `json:"Shared Hit Blocks"`
			SharedRead float64 `json:"Shared Read Blocks"`
		} `json:"Plan"`
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) == 1 {
		_ = json.Unmarshal(arr[0], &buffers)
	}
	return plans[0].Plan, plans[0].ExecutionTime, buffers.Plan.SharedHit + buffers.Plan.SharedRead, nil
}

// seedSearchableTenant writes 10k current and 10k closed decisions for one tenant, with 50 matching
// "production firewall" / "deny-egress-*" so keyword queries have realistic selectivity.
func seedSearchableTenant(t *testing.T, r registryDB, tenant uuid.UUID) {
	t.Helper()
	org := r.scope(t, tenant, uuid.Nil, "org", "acme")
	_, err := pgtest.Exec(t.Context(), r.app, tenant.String(), `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		SELECT gen_random_uuid(), 1, $1::uuid,
		       CASE WHEN g <= 50 THEN
		           jsonb_build_object(
		               'id', '01J9Z0000000000000000' || lpad(g::text, 5, '0'),
		               'slug', 'deny-egress-rule-' || g,
		               'title', 'Production firewall egress policy ' || g,
		               'statement', 'Block unrestricted egress on production firewalls.',
		               'tags', jsonb_build_array('networking', 'iso-27001')
		           )
		       ELSE
		           jsonb_build_object(
		               'id', '01J9Z9000000000000000' || lpad(g::text, 5, '0'),
		               'slug', 'service-standard-' || g,
		               'title', 'Standard engineering policy ' || g,
		               'statement', 'Keep service dependencies updated and documented.',
		               'tags', jsonb_build_array('platform', 'ops')
		           )
		       END,
		       ARRAY[$2::uuid],
		       '[2026-01-01,)'
		FROM generate_series(1, $3::int) AS g`, tenant, org, decisionsPerTenant)
	if err != nil {
		t.Fatalf("seed searchable decisions: %v", err)
	}
	// Revise every decision once so the history table also holds 10k closed rows.
	if _, err := pgtest.Exec(t.Context(), r.app, tenant.String(), `
		UPDATE registry.decision_version
		SET version = 2, body = body || '{"revised": true}'
		WHERE tenant_id = $1`, tenant); err != nil {
		t.Fatalf("seed searchable history: %v", err)
	}
}

// Guards the acceptance criteria of IPSO-195 (ADR-0169): SearchDecisions and the keyword filter of
// ListDecisionHealth must use decision_search_term_pkey under row-level security as ipso_app,
// without scanning and discarding the rest of the tenant's decisions.
func TestKeywordReadUsesTheSearchTermIndexUnderRowLevelSecurity(t *testing.T) {
	r := newRegistryDB(t)
	seedSearchableTenant(t, r, tenantA)
	seedSearchableTenant(t, r, tenantB)
	for _, table := range []string{"scope", "scope_history", "scope_closure", "scope_closure_history", "decision_version", "decision_version_history", "decision_scope_ref", "decision_search_term"} {
		if _, err := r.admin.ExecContext(t.Context(), `ANALYZE registry.`+table); err != nil {
			t.Fatal(err)
		}
	}
	const tenantRows = 2 * decisionsPerTenant
	valid := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	known := time.Now().Add(time.Minute)

	queries := []struct {
		name string
		q    string
	}{
		{"single-term prefix", "fire"},
		{"multi-term prefix", "prod fire"},
		{"slug prefix", "deny-eg"},
		{"tag prefix", "iso-27"},
	}

	err := readTx(t.Context(), r.app, tenantA, func(ctx context.Context, tx *sql.Tx) error {
		var user, tenant string
		var super, bypass bool
		if err := tx.QueryRowContext(ctx, `
			SELECT current_user, current_setting('ipso.tenant'), rolsuper, rolbypassrls
			FROM pg_catalog.pg_roles WHERE rolname = current_user`).Scan(&user, &tenant, &super, &bypass); err != nil {
			t.Fatal(err)
		}
		if user != pgtest.App || super || bypass || tenant != tenantA.String() {
			t.Fatalf("the session is %q (superuser %t, BYPASSRLS %t) for tenant %q, want %q with neither, for tenant A", user, super, bypass, tenant, pgtest.App)
		}

		for _, tc := range queries {
			terms, err := searchTerms(tc.q)
			if err != nil || len(terms) == 0 {
				t.Fatalf("%s: terms=%v err=%v", tc.name, terms, err)
			}

			searchStmt, searchArgs := searchDecisionsQuery(terms, valid, known, nil, 50)
			plan, ms, bufs, err := explainAnalyzeBuffers(ctx, tx, searchStmt, searchArgs...)
			if err != nil {
				t.Fatalf("SearchDecisions (%s): %v", tc.name, err)
			}
			t.Logf("SearchDecisions (%s): %.2f ms, %.0f buffers", tc.name, ms, bufs)
			if problems := searchPlanProblems(plan, tenantRows); len(problems) > 0 {
				t.Errorf("SearchDecisions (%s): %s", tc.name, strings.Join(problems, "; "))
			}

			healthStmt, healthArgs := listDecisionHealthQuery(terms, known, nil, "", valid, 50)
			plan, ms, bufs, err = explainAnalyzeBuffers(ctx, tx, healthStmt, healthArgs...)
			if err != nil {
				t.Fatalf("ListDecisionHealth (%s): %v", tc.name, err)
			}
			t.Logf("ListDecisionHealth (%s): %.2f ms, %.0f buffers", tc.name, ms, bufs)
			if problems := searchPlanProblems(plan, tenantRows); len(problems) > 0 {
				t.Errorf("ListDecisionHealth (%s): %s", tc.name, strings.Join(problems, "; "))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Negative meta-checks: the plan check must reject both the legacy FTS+ILIKE query and the new
	// query when index scans are turned off.
	err = readTx(t.Context(), r.app, tenantA, func(ctx context.Context, tx *sql.Tx) error {
		plan, ms, bufs, err := explainAnalyzeBuffers(ctx, tx, legacyKeywordRead, valid, known, nil, 50, "firewall", "firewall")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("legacyKeywordRead (firewall): %.2f ms, %.0f buffers", ms, bufs)
		if len(searchPlanProblems(plan, tenantRows)) == 0 {
			t.Error("searchPlanProblems accepted the legacy FTS+ILIKE scan, so it would not catch a regression")
		}

		for _, setting := range []string{"enable_indexscan", "enable_bitmapscan", "enable_indexonlyscan"} {
			if _, err := tx.ExecContext(ctx, "SET LOCAL "+setting+" = off"); err != nil {
				t.Fatal(err)
			}
		}
		fireTerms, err := searchTerms("fire")
		if err != nil {
			t.Fatal(err)
		}
		stmt, args := searchDecisionsQuery(fireTerms, valid, known, nil, 50)
		plan, _, _, err = explainAnalyzeBuffers(ctx, tx, stmt, args...)
		if err != nil {
			t.Fatal(err)
		}
		if len(searchPlanProblems(plan, tenantRows)) == 0 {
			t.Error("searchPlanProblems accepted a sequential plan with index scans disabled")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestKeywordSearchSemanticsAndSensitiveRedaction(t *testing.T) {
	r := newRegistryDB(t)
	ctx := t.Context()
	orgA := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	orgB := r.scope(t, tenantB, uuid.Nil, "org", "acme")

	writeBody := func(tenant uuid.UUID, id uuid.UUID, version int, body string, scope uuid.UUID) {
		t.Helper()
		if _, err := pgtest.Exec(ctx, r.app, tenant.String(), `
			INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
			VALUES ($1::uuid, $2::int, $3::uuid, $4::jsonb, ARRAY[$5::uuid], '[2026-01-01,)')`,
			id, version, tenant, body, scope); err != nil {
			t.Fatal(err)
		}
	}

	fwID := uuid.MustParse("00000000-0000-7000-8000-000000000101")
	revisedID := uuid.MustParse("00000000-0000-7000-8000-000000000102")
	secretID := uuid.MustParse("00000000-0000-7000-8000-000000000103")
	becameSecretID := uuid.MustParse("00000000-0000-7000-8000-000000000104")
	tenantBID := uuid.MustParse("00000000-0000-7000-8000-000000000105")

	writeBody(tenantA, fwID, 1, `{"id":"01J9Z000000000000000000101","slug":"deny-egress-prod","title":"Production firewall rules","statement":"Never allow 0.0.0.0/0 egress.","tags":["networking","iso-27001"]}`, orgA)
	writeBody(tenantA, revisedID, 1, `{"id":"01J9Z000000000000000000102","slug":"tls-policy","title":"Legacy cipher suite","statement":"Disable legacy SSL."}`, orgA)
	writeBody(tenantA, secretID, 1, `{"id":"01J9Z000000000000000000103","slug":"vault-host","title":"Confidential firewall enclave","statement":"Internal secret endpoint.","tags":["sensitive","vault-secret"]}`, orgA)
	writeBody(tenantA, becameSecretID, 1, `{"id":"01J9Z000000000000000000104","slug":"hsm-location","title":"Datacenter rack forty-two","statement":"Physical HSM cage.","tags":["hardware"]}`, orgA)
	writeBody(tenantB, tenantBID, 1, `{"id":"01J9Z000000000000000000105","slug":"deny-egress-prod","title":"Production firewall rules","statement":"Tenant B firewall."}`, orgB)

	beforeRevise := mark(t, r.admin)

	// Revise revisedID to drop "legacy" and transition becameSecretID to sensitive.
	if _, err := pgtest.Exec(ctx, r.app, tenantA.String(), `
		UPDATE registry.decision_version
		SET version = 2,
		    body = '{"id":"01J9Z000000000000000000102","slug":"tls-policy","title":"Modern TLS 1.3","statement":"Require TLS 1.3 everywhere."}'
		WHERE decision_id = $1::uuid`, revisedID); err != nil {
		t.Fatal(err)
	}
	if _, err := pgtest.Exec(ctx, r.app, tenantA.String(), `
		UPDATE registry.decision_version
		SET version = 2,
		    body = '{"id":"01J9Z000000000000000000104","slug":"hsm-location","title":"Datacenter rack forty-two","statement":"Physical HSM cage.","tags":["hardware","sensitive"]}'
		WHERE decision_id = $1::uuid`, becameSecretID); err != nil {
		t.Fatal(err)
	}

	valid := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	now := mark(t, r.admin)
	page := Page{Limit: 50}

	assertMatch := func(name, q string, known time.Time, wantIDs ...uuid.UUID) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			decs, err := SearchDecisions(ctx, r.app, tenantA, q, valid, known, page)
			if err != nil {
				t.Fatalf("SearchDecisions(%q): %v", q, err)
			}
			gotDec := make([]uuid.UUID, len(decs))
			for i, d := range decs {
				gotDec[i] = d.ID
			}
			if len(gotDec) != len(wantIDs) {
				t.Fatalf("SearchDecisions(%q) returned %v, want %v", q, gotDec, wantIDs)
			}
			for i := range wantIDs {
				if gotDec[i] != wantIDs[i] {
					t.Fatalf("SearchDecisions(%q) returned %v, want %v", q, gotDec, wantIDs)
				}
			}

			health, err := ListDecisionHealth(ctx, r.app, tenantA, HealthFilter{
				Query:   q,
				ValidAt: valid,
				KnownAt: known,
				Page:    page,
			})
			if err != nil {
				t.Fatalf("ListDecisionHealth(%q): %v", q, err)
			}
			if len(health) != len(wantIDs) {
				t.Fatalf("ListDecisionHealth(%q) returned %d rows, want %d", q, len(health), len(wantIDs))
			}
			for i := range wantIDs {
				if health[i].ID != wantIDs[i].String() {
					t.Fatalf("ListDecisionHealth(%q)[%d] = %s, want %s", q, i, health[i].ID, wantIDs[i])
				}
			}
		})
	}

	// Single-word prefix, multi-word prefix in reversed order, slug prefix, tag, EDR id.
	assertMatch("single prefix skips sensitive title", "fire", now, fwID)
	assertMatch("multi-word prefix any order", "fire prod", now, fwID)
	assertMatch("slug prefix", "deny-eg", now, fwID)
	assertMatch("tag prefix", "iso-27", now, fwID)
	assertMatch("tag token", "27001", now, fwID)
	assertMatch("edr id prefix", "01j9z000000000000000000101", now, fwID)
	assertMatch("punctuation only returns empty", "--- ???", now)

	// Revised version: dropped term "legacy" does not match at now, still matches at historical known.
	assertMatch("dropped term excluded at now", "legacy", now)
	assertMatch("dropped term found at historical known", "legacy", beforeRevise, revisedID)
	assertMatch("new term found at now", "modern", now, revisedID)

	// Sensitive decisions: match slug and EDR id only, never title/statement/tags.
	assertMatch("sensitive matched by slug prefix", "vault-ho", now, secretID)
	assertMatch("sensitive matched by edr id", "01j9z000000000000000000103", now, secretID)
	assertMatch("sensitive not matched by title", "confidential", now)
	assertMatch("sensitive not matched by statement", "enclave", now)
	assertMatch("sensitive not matched by tag", "vault-secret", now)

	// Non-sensitive v1 -> sensitive v2: title term "datacenter" must not match v2 at now, even though
	// v1 indexed it in the append-only lookup table, while slug still matches.
	assertMatch("transitioned sensitive not matched by old title at now", "datacenter", now)
	assertMatch("transitioned sensitive matched by slug at now", "hsm-loc", now, becameSecretID)
	assertMatch("transitioned sensitive matched by old title at v1 known", "datacenter", beforeRevise, becameSecretID)

	// Tenant isolation: tenant B only sees its own decision, never tenant A's.
	bDecs, err := SearchDecisions(ctx, r.app, tenantB, "fire", valid, now, page)
	if err != nil {
		t.Fatal(err)
	}
	if len(bDecs) != 1 || bDecs[0].ID != tenantBID {
		t.Fatalf("tenant B SearchDecisions('fire') = %+v, want only %s", bDecs, tenantBID)
	}
	bHealth, err := ListDecisionHealth(ctx, r.app, tenantB, HealthFilter{Query: "vault-ho", ValidAt: valid, KnownAt: now, Page: page})
	if err != nil {
		t.Fatal(err)
	}
	if len(bHealth) != 0 {
		t.Fatalf("tenant B leaked tenant A sensitive decision via ListDecisionHealth: %+v", bHealth)
	}
}
