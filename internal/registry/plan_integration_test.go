//go:build integration

package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

// overlapOnlyRead is the decisions read as it was before ADR-0168: the overlap operator is not leakproof,
// so under row-level security no index on scope_refs is a legal access path and this reads every row of
// the tenant. The test keeps it to show that its plan check rejects that plan, and that the lookup returns
// what this read returns.
const overlapOnlyRead = `
SELECT DISTINCT ON (d.decision_id) d.decision_id, d.version, d.body
FROM registry.decision_version_all d
WHERE d.scope_refs && $1::uuid[]
  AND d.valid_period @> $2::timestamptz
  AND d.sys_period @> $3::timestamptz
  AND d.tenant_id = ipso.current_tenant()
ORDER BY d.decision_id, d.version DESC`

// planNode is the part of a JSON plan that the check reads. Rows Removed by Filter and Actual Loops are
// numbers per loop, so the rows a node removed in all are their product.
type planNode struct {
	NodeType    string     `json:"Node Type"`
	Relation    string     `json:"Relation Name"`
	Index       string     `json:"Index Name"`
	IndexCond   string     `json:"Index Cond"`
	RecheckCond string     `json:"Recheck Cond"`
	Removed     float64    `json:"Rows Removed by Filter"`
	Loops       float64    `json:"Actual Loops"`
	Plans       []planNode `json:"Plans"`
}

func (n planNode) walk(visit func(planNode)) {
	visit(n)
	for _, child := range n.Plans {
		child.walk(visit)
	}
}

// explainAnalyze runs the statement with the planner's own choices and returns its plan with the rows
// that each node saw.
func explainAnalyze(ctx context.Context, tx *sql.Tx, stmt string, args ...any) (planNode, error) {
	var raw []byte
	if err := tx.QueryRowContext(ctx, "EXPLAIN (ANALYZE, FORMAT JSON) "+stmt, args...).Scan(&raw); err != nil {
		return planNode{}, err
	}
	var plans []struct {
		Plan planNode `json:"Plan"`
	}
	if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
		return planNode{}, fmt.Errorf("unreadable plan: %v", err)
	}
	return plans[0].Plan, nil
}

// planProblems is what is wrong with the plan of a decisions read, as an empty list when nothing is. The
// read is right when the scope lookup is read by an index on the scope ids, every version row is reached
// by an index condition on the decision id, and the tenant's other rows are not read and thrown away.
// tenantRows is the number of version rows of the tenant, current and closed.
func planProblems(root planNode, tenantRows int) []string {
	var problems []string
	lookup := false
	removed := 0.0
	root.walk(func(n planNode) {
		if n.Index == "decision_scope_ref_pkey" && strings.Contains(n.IndexCond, "scope_id") {
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
		problems = append(problems, "no node reads decision_scope_ref_pkey by scope_id")
	}
	if limit := float64(tenantRows) / 10; removed > limit {
		problems = append(problems, fmt.Sprintf("the version rows removed by filter are %.0f of %d, over %.0f", removed, tenantRows, limit))
	}
	return problems
}

// The decisions read is the one every check, waiver and audit query makes, and under row-level security
// the planner may only use an index whose operator is leakproof. This test runs the real statements as
// the application role with a tenant set, which the test of ADR-0051 did not: it ran as the superuser,
// where the policies do not apply, so it passed while the read scanned the whole tenant (IPSO-194).
func TestDecisionsReadUsesTheScopeIndexUnderRowLevelSecurity(t *testing.T) {
	r := newRegistryDB(t)
	a := seedTenant(t, r, tenantA)
	seedTenant(t, r, tenantB)
	for _, table := range []string{"scope", "scope_history", "scope_closure", "scope_closure_history", "decision_version", "decision_version_history", "decision_scope_ref"} {
		if _, err := r.admin.ExecContext(t.Context(), `ANALYZE registry.`+table); err != nil {
			t.Fatal(err)
		}
	}
	const tenantRows = 2 * decisionsPerTenant

	subjects := []Subject{
		{Repo: a.repos[31].name, Path: a.repos[31].dir + "/src/main.go", Env: "prod"},
		{Repo: a.repos[62].name},
		{Repo: a.repos[93].name, Path: a.repos[93].dir + "/x.go", Env: "dev"},
	}
	valid := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	known := time.Now().Add(time.Minute)

	// scopesOf reads the scopes of a subject as Resolve does, inside the same kind of transaction.
	scopesOf := func(ctx context.Context, tx *sql.Tx, s Subject) []uuid.UUID {
		t.Helper()
		sub, err := newSubject(s)
		if err != nil {
			t.Fatal(err)
		}
		matched, err := matchingScopes(ctx, tx, sub, known)
		if err != nil {
			t.Fatal(err)
		}
		scopes, err := ancestorsOf(ctx, tx, matched, known)
		if err != nil {
			t.Fatal(err)
		}
		if len(scopes) == 0 {
			t.Fatalf("subject %+v matches no scope, so its plan proves nothing", s)
		}
		return scopes
	}

	err := readTx(t.Context(), r.app, tenantA, func(ctx context.Context, tx *sql.Tx) error {
		// The plan is only evidence when row-level security applies to the session.
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

		for i, s := range subjects {
			scopes := scopesOf(ctx, tx, s)
			for name, stmt := range map[string]string{"decisionsInForce": decisionsInForce, "decisionsInForceForScopes": decisionsInForceForScopes} {
				plan, err := explainAnalyze(ctx, tx, stmt, scopes, valid, known)
				if err != nil {
					t.Fatalf("subject %d, %s: %v", i, name, err)
				}
				if problems := planProblems(plan, tenantRows); len(problems) > 0 {
					t.Errorf("subject %d, %s: %s", i, name, strings.Join(problems, "; "))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The check has to be able to fail. The overlap-only read is the plan that IPSO-194 reported, and the
	// lookup read with every index scan turned off is a plan that reads whole tables.
	err = readTx(t.Context(), r.app, tenantA, func(ctx context.Context, tx *sql.Tx) error {
		scopes := scopesOf(ctx, tx, subjects[0])
		plan, err := explainAnalyze(ctx, tx, overlapOnlyRead, scopes, valid, known)
		if err != nil {
			t.Fatal(err)
		}
		if len(planProblems(plan, tenantRows)) == 0 {
			t.Error("the check accepts the plan of the read by overlap alone, so it would not catch a return to it")
		}

		for _, setting := range []string{"enable_indexscan", "enable_bitmapscan", "enable_indexonlyscan"} {
			if _, err := tx.ExecContext(ctx, "SET LOCAL "+setting+" = off"); err != nil {
				t.Fatal(err)
			}
		}
		plan, err = explainAnalyze(ctx, tx, decisionsInForce, scopes, valid, known)
		if err != nil {
			t.Fatal(err)
		}
		if len(planProblems(plan, tenantRows)) == 0 {
			t.Error("the check accepts a plan that reads the tables without an index")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The lookup only narrows the candidates, so the answer is the one the overlap test alone gives.
	err = readTx(t.Context(), r.app, tenantA, func(ctx context.Context, tx *sql.Tx) error {
		for i, s := range subjects {
			scopes := scopesOf(ctx, tx, s)
			got, want := versions(t, ctx, tx, decisionsInForce, scopes, valid, known), versions(t, ctx, tx, overlapOnlyRead, scopes, valid, known)
			if len(want) == 0 {
				t.Errorf("subject %d: the read by overlap returns no decision, so the comparison proves nothing", i)
			}
			if !slices.Equal(got, want) {
				t.Errorf("subject %d: the lookup read returns %d decisions and the read by overlap %d", i, len(got), len(want))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// versions is the decision id and version of every row a decisions read returns, in the order it returns them.
func versions(t *testing.T, ctx context.Context, tx *sql.Tx, stmt string, args ...any) []string {
	t.Helper()
	rows, err := tx.QueryContext(ctx, stmt, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id uuid.UUID
		var version int
		var body []byte
		if err := rows.Scan(&id, &version, &body); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s/%d", id, version))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
