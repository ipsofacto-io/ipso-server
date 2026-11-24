package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso/pkg/mcptools"
)

// DefaultMaxAgeDays is the fallback freshness window when neither the check nor tenant/environment policy sets one (ADR-0163).
const DefaultMaxAgeDays = 30

// HealthFilter narrows GET /v1/decisions/health and MCP decisions.health queries.
type HealthFilter struct {
	Query   string
	Repo    string
	Env     string
	ValidAt time.Time
	KnownAt time.Time
	Page    Page
}

type rawDecisionRow struct {
	ID        uuid.UUID
	Version   int
	Body      []byte
	ValidFrom time.Time
	ValidTo   *time.Time
}

type storedVerdictSnap struct {
	CheckIndex    int
	SourceKind    string
	Command       string
	Repo          string
	Env           string
	Result        string
	Violations    int
	EvaluatedAt   time.Time
	ModelID       string
	PromptVersion string
}

// ComputeValidityAndCompliance evaluates the pure Validity and Compliance axes of one decision from
// its parsed body, validity bounds, open premise reasons, latest verdicts, active waivers, and freshness map.
func ComputeValidityAndCompliance(
	id uuid.UUID,
	body []byte,
	validFrom time.Time,
	validTo *time.Time,
	supersededBy string,
	scopeRepos []string,
	openPremises []mcptools.PremiseAlert,
	verdicts []storedVerdictSnap,
	hasActiveWaiver bool,
	freshness map[string]int,
	filterEnv string,
	now time.Time,
) mcptools.DecisionHealth {
	var parsed struct {
		ID          string `json:"id"`
		Slug        string `json:"slug"`
		Title       string `json:"title"`
		Statement   string `json:"statement"`
		Status      string `json:"status"`
		Criticality string `json:"criticality"`
		Sensitive   bool   `json:"sensitive"`
		ReviewBy    string `json:"review_by"`
		Checks      []struct {
			Engine     string `json:"engine"`
			Target     string `json:"target"`
			Mode       string `json:"mode"`
			Status     string `json:"status"`
			MaxAgeDays int    `json:"max_age_days"`
		} `json:"checks"`
	}
	_ = json.Unmarshal(body, &parsed)

	edrID := parsed.ID
	if edrID == "" {
		edrID = id.String()
	}
	status := parsed.Status
	if status == "" {
		status = "accepted"
	}
	crit := parsed.Criticality
	if crit == "" {
		crit = "warning"
	}

	validityState := "valid"
	switch {
	case supersededBy != "" || status == "superseded":
		validityState = "superseded"
	case (validTo != nil && !now.Before(*validTo)) || status == "deprecated" || status == "rejected":
		validityState = "expired"
	case len(openPremises) > 0:
		validityState = "needs_review"
	case parsed.ReviewBy != "":
		if reviewDate, err := time.Parse("2006-01-02", parsed.ReviewBy); err == nil && now.After(reviewDate.Add(24*time.Hour)) {
			validityState = "needs_review"
		}
	}

	var validToStr string
	if validTo != nil {
		validToStr = validTo.UTC().Format(time.RFC3339)
	}
	if openPremises == nil {
		openPremises = []mcptools.PremiseAlert{}
	}

	validity := mcptools.ValidityHealth{
		State:              validityState,
		Status:             status,
		ValidFrom:          validFrom.UTC().Format(time.RFC3339),
		ValidTo:            validToStr,
		ReviewBy:           parsed.ReviewBy,
		SupersededBy:       supersededBy,
		OpenPremiseReasons: openPremises,
	}

	scopes := []mcptools.ScopeCompliance{}
	overall := "unverified"
	activeChecks := 0
	for idx, ch := range parsed.Checks {
		if ch.Engine == "llm-advisory" {
			continue
		}
		activeChecks++
		maxAge := resolveMaxAgeDays(ch.MaxAgeDays, filterEnv, freshness)

		var latestChange, latestLive *storedVerdictSnap
		for i := range verdicts {
			v := &verdicts[i]
			if v.CheckIndex != idx {
				continue
			}
			if filterEnv != "" && v.Env != "" && !strings.EqualFold(v.Env, filterEnv) {
				continue
			}
			if v.SourceKind == "live" {
				if latestLive == nil || v.EvaluatedAt.After(latestLive.EvaluatedAt) {
					latestLive = v
				}
			} else {
				if latestChange == nil || v.EvaluatedAt.After(latestChange.EvaluatedAt) {
					latestChange = v
				}
			}
		}

		chosen := latestLive
		if chosen == nil || (latestChange != nil && latestChange.EvaluatedAt.After(chosen.EvaluatedAt)) {
			chosen = latestChange
		}

		repoLabel := strings.Join(scopeRepos, ", ")
		envLabel := filterEnv
		if chosen != nil {
			if chosen.Repo != "" {
				repoLabel = chosen.Repo
			}
			if envLabel == "" {
				envLabel = chosen.Env
			}
		}

		entry := mcptools.ScopeCompliance{
			Repo:   repoLabel,
			Env:    envLabel,
			Waived: hasActiveWaiver,
		}
		if latestChange != nil {
			stale := now.Sub(latestChange.EvaluatedAt) > time.Duration(maxAge)*24*time.Hour
			entry.LatestChange = &mcptools.VerdictSummary{
				SourceKind:    "change",
				Command:       nonEmptyCmd(latestChange.Command, ch.Engine),
				Result:        latestChange.Result,
				Violations:    latestChange.Violations,
				EvaluatedAt:   latestChange.EvaluatedAt.UTC().Format(time.RFC3339),
				Stale:         stale,
				MaxAgeDays:    maxAge,
				ModelID:       latestChange.ModelID,
				PromptVersion: latestChange.PromptVersion,
			}
		}
		if latestLive != nil {
			stale := now.Sub(latestLive.EvaluatedAt) > time.Duration(maxAge)*24*time.Hour
			entry.LatestLive = &mcptools.VerdictSummary{
				SourceKind:    "live",
				Command:       nonEmptyCmd(latestLive.Command, ch.Engine),
				Result:        latestLive.Result,
				Violations:    latestLive.Violations,
				EvaluatedAt:   latestLive.EvaluatedAt.UTC().Format(time.RFC3339),
				Stale:         stale,
				MaxAgeDays:    maxAge,
				ModelID:       latestLive.ModelID,
				PromptVersion: latestLive.PromptVersion,
			}
		}

		switch {
		case chosen == nil:
			entry.State = "unverified"
		case chosen.Result == "fail" || chosen.Result == "error":
			if chosen.Result == "fail" && hasActiveWaiver {
				entry.State = "waived"
			} else {
				entry.State = "violated"
			}
		case chosen.Result == "waived" || (hasActiveWaiver && chosen.Violations > 0):
			entry.State = "waived"
			entry.Baselined = chosen.Result == "waived" && !hasActiveWaiver
		default:
			if now.Sub(chosen.EvaluatedAt) > time.Duration(maxAge)*24*time.Hour {
				entry.State = "stale"
			} else {
				entry.State = "compliant"
			}
		}
		scopes = append(scopes, entry)
	}

	if activeChecks > 0 {
		overall = aggregateCompliance(scopes)
	}

	title := parsed.Title
	if parsed.Sensitive {
		title = ""
	}

	return mcptools.DecisionHealth{
		ID:          edrID,
		Slug:        parsed.Slug,
		Title:       title,
		Criticality: crit,
		Sensitive:   parsed.Sensitive,
		Validity:    validity,
		Compliance: mcptools.ComplianceHealth{
			State:  overall,
			Scopes: scopes,
		},
	}
}

func nonEmptyCmd(cmd, fallback string) string {
	if cmd != "" {
		return cmd
	}
	return fallback
}

func resolveMaxAgeDays(checkMax int, env string, freshness map[string]int) int {
	if checkMax >= 1 && checkMax <= 365 {
		return checkMax
	}
	if env != "" {
		if age, ok := freshness[env]; ok && age >= 1 {
			return age
		}
	}
	if age, ok := freshness[""]; ok && age >= 1 {
		return age
	}
	return DefaultMaxAgeDays
}

func aggregateCompliance(scopes []mcptools.ScopeCompliance) string {
	hasWaived := false
	hasStale := false
	hasUnverified := false
	hasCompliant := false
	for _, s := range scopes {
		switch s.State {
		case "violated":
			return "violated"
		case "stale":
			hasStale = true
		case "unverified":
			hasUnverified = true
		case "waived":
			hasWaived = true
		case "compliant":
			hasCompliant = true
		}
	}
	switch {
	case hasStale:
		return "stale"
	case hasUnverified:
		return "unverified"
	case hasWaived:
		return "waived"
	case hasCompliant:
		return "compliant"
	default:
		return "unverified"
	}
}

// DecisionHealthByRef computes unified Validity and Compliance for one decision referenced by UUID, EDR ULID, or slug (ADR-0163).
func DecisionHealthByRef(ctx context.Context, db *sql.DB, tenant uuid.UUID, ref, repo, env string, validAt, knownAt time.Time) (mcptools.DecisionHealth, error) {
	ref = strings.TrimSpace(ref)
	repo = strings.ToLower(strings.TrimSpace(repo))
	env = strings.TrimSpace(env)
	if tenant == uuid.Nil || ref == "" || validAt.IsZero() || knownAt.IsZero() {
		return mcptools.DecisionHealth{}, fmt.Errorf("%w: tenant, ref, and timestamps are required", ErrInvalidQuery)
	}
	var out mcptools.DecisionHealth
	err := readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		var parsedUUID uuid.NullUUID
		if u, err := uuid.Parse(ref); err == nil && u != uuid.Nil {
			parsedUUID = uuid.NullUUID{UUID: u, Valid: true}
		}
		var row rawDecisionRow
		var upper sql.NullTime
		err := tx.QueryRowContext(ctx, `
			SELECT d.decision_id, d.version, d.body, lower(d.valid_period), upper(d.valid_period)
			FROM registry.decision_version_all d
			WHERE d.tenant_id = ipso.current_tenant()
			  AND d.sys_period @> $1::timestamptz
			  AND (
			      ($2::uuid IS NOT NULL AND d.decision_id = $2::uuid)
			      OR d.body->>'id' = $3
			      OR d.body->>'slug' = $3
			  )
			ORDER BY (d.valid_period @> $4::timestamptz) DESC, d.version DESC
			LIMIT 1`, knownAt, parsedUUID, ref, validAt).Scan(&row.ID, &row.Version, &row.Body, &row.ValidFrom, &upper)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read decision health: %w", err)
		}
		if upper.Valid {
			t := upper.Time
			row.ValidTo = &t
		}
		items, err := hydrateHealthRows(ctx, tx, []rawDecisionRow{row}, repo, env, validAt, knownAt)
		if err != nil {
			return err
		}
		out = items[0]
		return nil
	})
	return out, err
}

// ListDecisionHealth returns a page of unified Validity and Compliance records, supporting full-text search on q and repo/env filters.
func ListDecisionHealth(ctx context.Context, db *sql.DB, tenant uuid.UUID, f HealthFilter) ([]mcptools.DecisionHealth, error) {
	if err := checkList(tenant, f.Page, f.ValidAt, f.KnownAt); err != nil {
		return nil, err
	}
	q := strings.TrimSpace(f.Query)
	repo := strings.ToLower(strings.TrimSpace(f.Repo))
	env := strings.TrimSpace(f.Env)
	if len(q) > 256 || len(repo) > 140 || len(env) > 256 {
		return nil, fmt.Errorf("%w: query or filter exceeds maximum length", ErrInvalidQuery)
	}

	out := []mcptools.DecisionHealth{}
	err := readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT DISTINCT ON (d.decision_id) d.decision_id, d.version, d.body, lower(d.valid_period), upper(d.valid_period)
			FROM registry.decision_version_all d
			WHERE d.tenant_id = ipso.current_tenant()
			  AND d.sys_period @> $1::timestamptz
			  AND ($2::uuid IS NULL OR d.decision_id < $2::uuid)
			  AND (
			      $3 = ''
			      OR to_tsvector('simple',
			          coalesce(d.body->>'title', '') || ' ' ||
			          coalesce(d.body->>'slug', '') || ' ' ||
			          coalesce(d.body->>'statement', '')) @@ plainto_tsquery('simple', $3)
			      OR coalesce(d.body->>'slug', '') ILIKE '%' || $3 || '%'
			      OR coalesce(d.body->>'title', '') ILIKE '%' || $3 || '%'
			  )
			  AND (
			      $4 = ''
			      OR EXISTS (
			          SELECT 1
			          FROM registry.decision_scope ds
			          JOIN registry.scope_all s ON s.tenant_id = ds.tenant_id AND s.id = ds.scope_id
			          WHERE ds.tenant_id = d.tenant_id
			            AND ds.decision_id = d.decision_id
			            AND ds.version = d.version
			            AND s.sys_period @> $1::timestamptz
			            AND (
			                (s.kind = 'repo' AND s.selector = $4)
			                OR (s.kind = 'org' AND split_part($4, '/', 1) = s.selector)
			            )
			      )
			  )
			ORDER BY d.decision_id DESC, (d.valid_period @> $5::timestamptz) DESC, d.version DESC
			LIMIT $6`,
			f.KnownAt, f.Page.before(), q, repo, f.ValidAt, f.Page.Limit)
		if err != nil {
			return fmt.Errorf("list decision health: %w", err)
		}
		defer func() { _ = rows.Close() }()

		var rawRows []rawDecisionRow
		for rows.Next() {
			var r rawDecisionRow
			var upper sql.NullTime
			if err := rows.Scan(&r.ID, &r.Version, &r.Body, &r.ValidFrom, &upper); err != nil {
				return err
			}
			if upper.Valid {
				t := upper.Time
				r.ValidTo = &t
			}
			rawRows = append(rawRows, r)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(rawRows) == 0 {
			return nil
		}
		hydrated, err := hydrateHealthRows(ctx, tx, rawRows, repo, env, f.ValidAt, f.KnownAt)
		if err != nil {
			return err
		}
		out = hydrated
		return nil
	})
	return out, err
}

func hydrateHealthRows(ctx context.Context, tx *sql.Tx, rows []rawDecisionRow, filterRepo, filterEnv string, validAt, knownAt time.Time) ([]mcptools.DecisionHealth, error) {
	ids := make([]uuid.UUID, len(rows))
	edrIDs := make([]string, 0, len(rows))
	slugs := make([]string, 0, len(rows))
	edrToDecision := make(map[string]uuid.UUID, len(rows))
	slugToDecision := make(map[string]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
		var meta struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
		}
		if json.Unmarshal(r.Body, &meta) == nil {
			if meta.ID != "" {
				edrIDs = append(edrIDs, meta.ID)
				edrToDecision[meta.ID] = r.ID
			}
			if meta.Slug != "" {
				slugs = append(slugs, meta.Slug)
				slugToDecision[meta.Slug] = r.ID
			}
		}
	}

	freshness := map[string]int{}
	fRows, err := tx.QueryContext(ctx, `
		SELECT env, max_age_days
		FROM verification.freshness_policy
		WHERE tenant_id = ipso.current_tenant()`)
	if err != nil {
		return nil, err
	}
	for fRows.Next() {
		var e string
		var age int
		if err := fRows.Scan(&e, &age); err != nil {
			_ = fRows.Close()
			return nil, err
		}
		freshness[e] = age
	}
	_ = fRows.Close()

	scopesByDecision := map[uuid.UUID][]string{}
	sRows, err := tx.QueryContext(ctx, `
		SELECT ds.decision_id, s.selector
		FROM registry.decision_scope ds
		JOIN registry.scope_all s ON s.tenant_id = ds.tenant_id AND s.id = ds.scope_id
		WHERE ds.tenant_id = ipso.current_tenant()
		  AND ds.decision_id = ANY($1::uuid[])
		  AND s.sys_period @> $2::timestamptz
		ORDER BY ds.decision_id, s.kind, s.selector`, ids, knownAt)
	if err != nil {
		return nil, err
	}
	for sRows.Next() {
		var did uuid.UUID
		var sel string
		if err := sRows.Scan(&did, &sel); err != nil {
			_ = sRows.Close()
			return nil, err
		}
		if !containsString(scopesByDecision[did], sel) {
			scopesByDecision[did] = append(scopesByDecision[did], sel)
		}
	}
	_ = sRows.Close()

	supersededBy := map[uuid.UUID]string{}
	supRows, err := tx.QueryContext(ctx, `
		SELECT s.from_decision_id, s.to_decision_id::text
		FROM registry.supersession s
		WHERE s.tenant_id = ipso.current_tenant()
		  AND s.from_decision_id = ANY($1::uuid[])
		  AND s.effective_at <= $2::timestamptz
		  AND s.sys_period @> $3::timestamptz`, ids, validAt, knownAt)
	if err != nil {
		return nil, err
	}
	for supRows.Next() {
		var from uuid.UUID
		var to string
		if err := supRows.Scan(&from, &to); err != nil {
			_ = supRows.Close()
			return nil, err
		}
		supersededBy[from] = to
	}
	_ = supRows.Close()

	openPremises := map[uuid.UUID][]mcptools.PremiseAlert{}
	pRows, err := tx.QueryContext(ctx, `
		SELECT r.decision_id, r.premise_id, e.url, e.pointer
		FROM registry.premise_reason r
		JOIN registry.premise_evaluation e ON e.tenant_id = r.tenant_id AND e.id = r.evaluation_id
		WHERE r.tenant_id = ipso.current_tenant()
		  AND r.decision_id = ANY($1::uuid[])
		  AND NOT EXISTS (
		      SELECT 1 FROM registry.premise_clearance c
		      WHERE c.tenant_id = r.tenant_id AND c.reason_id = r.id)
		ORDER BY r.id DESC`, ids)
	if err != nil {
		return nil, err
	}
	for pRows.Next() {
		var did uuid.UUID
		var pid, urlStr, ptr string
		if err := pRows.Scan(&did, &pid, &urlStr, &ptr); err != nil {
			_ = pRows.Close()
			return nil, err
		}
		openPremises[did] = append(openPremises[did], mcptools.PremiseAlert{
			PremiseID:  pid,
			ReasonCode: "premise_failed",
			Detail:     strings.TrimSpace(urlStr + " " + ptr),
		})
	}
	_ = pRows.Close()

	waivedDecisions := map[uuid.UUID]bool{}
	wRows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT w.decision_id
		FROM registry.waiver w
		WHERE w.tenant_id = ipso.current_tenant()
		  AND w.decision_id = ANY($1::uuid[])
		  AND w.valid_period @> $2::timestamptz
		  AND w.sys_period @> $3::timestamptz`, ids, validAt, knownAt)
	if err != nil {
		return nil, err
	}
	for wRows.Next() {
		var did uuid.UUID
		if err := wRows.Scan(&did); err != nil {
			_ = wRows.Close()
			return nil, err
		}
		waivedDecisions[did] = true
	}
	_ = wRows.Close()

	verdictsByDecision := map[uuid.UUID][]storedVerdictSnap{}
	if len(edrIDs) > 0 || len(slugs) > 0 {
		vRows, err := tx.QueryContext(ctx, `
			SELECT DISTINCT ON (v.decision_id, v.slug, v.check_index, u.source_kind)
			       v.decision_id, v.slug, v.check_index, u.source_kind, u.check_name, u.repo, u.env,
			       v.result, v.violations, u.evaluated_at, coalesce(v.model_id, ''), coalesce(v.prompt_version, '')
			FROM verification.verdict v
			JOIN verification.upload u ON u.tenant_id = v.tenant_id AND u.id = v.upload_id
			WHERE v.tenant_id = ipso.current_tenant()
			  AND u.sys_period @> $1::timestamptz
			  AND ($2 = '' OR u.repo = $2)
			  AND ($3 = '' OR u.env = '' OR u.env = $3)
			  AND (v.decision_id = ANY($4::text[]) OR v.slug = ANY($5::text[]))
			ORDER BY v.decision_id, v.slug, v.check_index, u.source_kind, u.evaluated_at DESC, v.id DESC`,
			knownAt, filterRepo, filterEnv, edrIDs, slugs)
		if err != nil {
			return nil, err
		}
		for vRows.Next() {
			var vEDRID, vSlug string
			var snap storedVerdictSnap
			if err := vRows.Scan(&vEDRID, &vSlug, &snap.CheckIndex, &snap.SourceKind, &snap.Command, &snap.Repo, &snap.Env,
				&snap.Result, &snap.Violations, &snap.EvaluatedAt, &snap.ModelID, &snap.PromptVersion); err != nil {
				_ = vRows.Close()
				return nil, err
			}
			if did, ok := edrToDecision[vEDRID]; ok {
				verdictsByDecision[did] = append(verdictsByDecision[did], snap)
			} else if did, ok := slugToDecision[vSlug]; ok {
				verdictsByDecision[did] = append(verdictsByDecision[did], snap)
			}
		}
		_ = vRows.Close()
	}

	out := make([]mcptools.DecisionHealth, len(rows))
	for i, r := range rows {
		out[i] = ComputeValidityAndCompliance(
			r.ID,
			r.Body,
			r.ValidFrom,
			r.ValidTo,
			supersededBy[r.ID],
			scopesByDecision[r.ID],
			openPremises[r.ID],
			verdictsByDecision[r.ID],
			waivedDecisions[r.ID],
			freshness,
			filterEnv,
			validAt,
		)
	}
	return out, nil
}

func containsString(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}
