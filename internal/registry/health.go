package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso/pkg/mcptools"
)

// DefaultMaxAgeDays is the fallback freshness window when neither the check nor tenant/environment policy sets one (ADR-0163).
const (
	DefaultMaxAgeDays     = 30
	DefaultProdMaxAgeDays = 7
)

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
	ScopeRefs []uuid.UUID
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

type scopeKey struct {
	Repo string
	Env  string
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
	isScopeWaived func(repo, env string) bool,
	freshness map[string]int,
	filterEnv string,
	now time.Time,
) mcptools.DecisionHealth {
	var parsed struct {
		ID          string   `json:"id"`
		Slug        string   `json:"slug"`
		Title       string   `json:"title"`
		Statement   string   `json:"statement"`
		Status      string   `json:"status"`
		Criticality string   `json:"criticality"`
		Sensitive   bool     `json:"sensitive"`
		Tags        []string `json:"tags"`
		ReviewBy    string   `json:"review_by"`
		Checks      []struct {
			Engine     string `json:"engine"`
			Target     string `json:"target"`
			Mode       string `json:"mode"`
			Status     string `json:"status"`
			MaxAgeDays int    `json:"max_age_days"`
		} `json:"checks"`
	}
	_ = json.Unmarshal(body, &parsed)

	recordID := id.String()
	if id == uuid.Nil && parsed.ID != "" {
		recordID = parsed.ID
	}
	status := parsed.Status
	if status == "" {
		status = "accepted"
	}
	crit := parsed.Criticality
	if crit == "" {
		crit = "warning"
	}
	isSensitive := parsed.Sensitive || slices.Contains(parsed.Tags, "sensitive")

	validityState := "valid"
	switch {
	case supersededBy != "" || status == "superseded":
		validityState = "superseded"
	case (validTo != nil && !now.Before(*validTo)) || status == "deprecated" || status == "rejected":
		validityState = "expired"
	case len(openPremises) > 0 || status == "needs-review" || status == "proposed":
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
	} else if isSensitive {
		redactedPremises := make([]mcptools.PremiseAlert, len(openPremises))
		for i, p := range openPremises {
			redactedPremises[i] = mcptools.PremiseAlert{
				PremiseID:  p.PremiseID,
				ReasonCode: p.ReasonCode,
			}
		}
		openPremises = redactedPremises
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

	type activeCheck struct {
		index      int
		engine     string
		maxAgeDays int
	}
	var active []activeCheck
	for idx, ch := range parsed.Checks {
		if ch.Engine == "llm-advisory" {
			continue
		}
		active = append(active, activeCheck{
			index:      idx,
			engine:     ch.Engine,
			maxAgeDays: ch.MaxAgeDays,
		})
	}

	scopes := []mcptools.ScopeCompliance{}
	overall := "unverified"
	if len(active) > 0 {
		seenKeys := map[scopeKey]bool{}
		reposWithVerdicts := map[string]bool{}
		var keys []scopeKey

		for i := range verdicts {
			v := &verdicts[i]
			if filterEnv != "" && !strings.EqualFold(v.Env, filterEnv) {
				continue
			}
			k := scopeKey{Repo: v.Repo, Env: v.Env}
			if !seenKeys[k] {
				seenKeys[k] = true
				keys = append(keys, k)
			}
			if v.Repo != "" {
				reposWithVerdicts[v.Repo] = true
			}
		}
		for _, repo := range scopeRepos {
			if !reposWithVerdicts[repo] {
				k := scopeKey{Repo: repo, Env: filterEnv}
				if !seenKeys[k] {
					seenKeys[k] = true
					keys = append(keys, k)
				}
			}
		}
		if len(keys) == 0 {
			keys = append(keys, scopeKey{Repo: "", Env: filterEnv})
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].Repo != keys[j].Repo {
				return keys[i].Repo < keys[j].Repo
			}
			return keys[i].Env < keys[j].Env
		})

		for _, k := range keys {
			scopeWaived := isScopeWaived != nil && isScopeWaived(k.Repo, k.Env)
			entry := mcptools.ScopeCompliance{
				Repo:   k.Repo,
				Env:    k.Env,
				Waived: scopeWaived,
			}
			var scopeStates []string
			var bestChangeState, bestLiveState string
			var bestChangeTime, bestLiveTime time.Time

			for _, ch := range active {
				maxAge := resolveMaxAgeDays(ch.maxAgeDays, k.Env, freshness)
				var latestChange, latestLive *storedVerdictSnap
				for i := range verdicts {
					v := &verdicts[i]
					if v.CheckIndex != ch.index || v.Repo != k.Repo {
						continue
					}
					if filterEnv != "" && !strings.EqualFold(v.Env, filterEnv) {
						continue
					}
					if !strings.EqualFold(v.Env, k.Env) {
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

				if latestChange == nil && latestLive == nil {
					scopeStates = append(scopeStates, "unverified")
					continue
				}

				var checkStreamStates []string
				if latestChange != nil {
					st, baselined, stale := classifyStreamVerdict(latestChange, maxAge, scopeWaived, now)
					checkStreamStates = append(checkStreamStates, st)
					if baselined {
						entry.Baselined = true
					}
					summary := &mcptools.VerdictSummary{
						SourceKind:    "change",
						Command:       nonEmptyCmd(latestChange.Command, ch.engine),
						Result:        latestChange.Result,
						Violations:    latestChange.Violations,
						EvaluatedAt:   latestChange.EvaluatedAt.UTC().Format(time.RFC3339),
						Stale:         stale,
						MaxAgeDays:    maxAge,
						ModelID:       latestChange.ModelID,
						PromptVersion: latestChange.PromptVersion,
					}
					if entry.LatestChange == nil || complianceRank(st) < complianceRank(bestChangeState) ||
						(complianceRank(st) == complianceRank(bestChangeState) && latestChange.EvaluatedAt.After(bestChangeTime)) {
						entry.LatestChange = summary
						bestChangeState = st
						bestChangeTime = latestChange.EvaluatedAt
					}
				}
				if latestLive != nil {
					st, baselined, stale := classifyStreamVerdict(latestLive, maxAge, scopeWaived, now)
					checkStreamStates = append(checkStreamStates, st)
					if baselined {
						entry.Baselined = true
					}
					summary := &mcptools.VerdictSummary{
						SourceKind:    "live",
						Command:       nonEmptyCmd(latestLive.Command, ch.engine),
						Result:        latestLive.Result,
						Violations:    latestLive.Violations,
						EvaluatedAt:   latestLive.EvaluatedAt.UTC().Format(time.RFC3339),
						Stale:         stale,
						MaxAgeDays:    maxAge,
						ModelID:       latestLive.ModelID,
						PromptVersion: latestLive.PromptVersion,
					}
					if entry.LatestLive == nil || complianceRank(st) < complianceRank(bestLiveState) ||
						(complianceRank(st) == complianceRank(bestLiveState) && latestLive.EvaluatedAt.After(bestLiveTime)) {
						entry.LatestLive = summary
						bestLiveState = st
						bestLiveTime = latestLive.EvaluatedAt
					}
				}
				scopeStates = append(scopeStates, worstState(checkStreamStates))
			}

			entry.State = worstState(scopeStates)
			scopes = append(scopes, entry)
		}
		overall = aggregateCompliance(scopes)
	}

	title := parsed.Title
	if isSensitive {
		title = ""
	}

	return mcptools.DecisionHealth{
		ID:          recordID,
		Slug:        parsed.Slug,
		Title:       title,
		Criticality: crit,
		Sensitive:   isSensitive,
		Validity:    validity,
		Compliance: mcptools.ComplianceHealth{
			State:  overall,
			Scopes: scopes,
		},
	}
}

func classifyStreamVerdict(v *storedVerdictSnap, maxAge int, hasActiveWaiver bool, now time.Time) (state string, baselined bool, stale bool) {
	stale = now.Sub(v.EvaluatedAt) > time.Duration(maxAge)*24*time.Hour
	switch {
	case v.Result == "error":
		return "violated", false, stale
	case v.Result == "fail" && !hasActiveWaiver:
		return "violated", false, stale
	case stale:
		return "stale", v.Result == "waived" && !hasActiveWaiver, true
	case v.Result == "waived" || v.Result == "fail" || (hasActiveWaiver && v.Violations > 0):
		return "waived", v.Result == "waived" && !hasActiveWaiver, false
	default:
		return "compliant", false, false
	}
}

func complianceRank(state string) int {
	switch state {
	case "violated":
		return 0
	case "stale":
		return 1
	case "unverified":
		return 2
	case "waived":
		return 3
	case "compliant":
		return 4
	default:
		return 2
	}
}

func worstState(states []string) string {
	if len(states) == 0 {
		return "unverified"
	}
	best := states[0]
	for _, s := range states[1:] {
		if complianceRank(s) < complianceRank(best) {
			best = s
		}
	}
	return best
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
	envKey := strings.ToLower(strings.TrimSpace(env))
	if envKey != "" {
		if age, ok := freshness[envKey]; ok && age >= 1 {
			return age
		}
		if age, ok := freshness[env]; ok && age >= 1 {
			return age
		}
	}
	if age, ok := freshness["default"]; ok && age >= 1 {
		return age
	}
	if age, ok := freshness[""]; ok && age >= 1 {
		return age
	}
	if envKey == "prod" {
		return DefaultProdMaxAgeDays
	}
	return DefaultMaxAgeDays
}

func aggregateCompliance(scopes []mcptools.ScopeCompliance) string {
	if len(scopes) == 0 {
		return "unverified"
	}
	states := make([]string, len(scopes))
	for i, s := range scopes {
		states[i] = s.State
	}
	return worstState(states)
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
		var refsText string
		var upper sql.NullTime
		err := tx.QueryRowContext(ctx, `
			SELECT d.decision_id, d.version, d.body, d.scope_refs::text, lower(d.valid_period), upper(d.valid_period)
			FROM registry.decision_version_all d
			WHERE d.tenant_id = ipso.current_tenant()
			  AND d.sys_period @> $1::timestamptz
			  AND (
			      ($2::uuid IS NOT NULL AND d.decision_id = $2::uuid)
			      OR d.body->>'id' = $3
			      OR d.body->>'slug' = $3
			  )
			ORDER BY (d.valid_period @> $4::timestamptz) DESC, d.version DESC
			LIMIT 1`, knownAt, parsedUUID, ref, validAt).Scan(&row.ID, &row.Version, &row.Body, &refsText, &row.ValidFrom, &upper)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read decision health: %w", err)
		}
		refs, err := parseUUIDArray(refsText)
		if err != nil {
			return err
		}
		row.ScopeRefs = refs
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
			SELECT DISTINCT ON (d.decision_id) d.decision_id, d.version, d.body, d.scope_refs::text, lower(d.valid_period), upper(d.valid_period)
			FROM registry.decision_version_all d
			WHERE d.tenant_id = ipso.current_tenant()
			  AND d.sys_period @> $1::timestamptz
			  AND ($2::uuid IS NULL OR d.decision_id < $2::uuid)
			  AND (
			      $3 = ''
			      OR (
			          NOT (coalesce(d.body->'tags', '[]'::jsonb) ? 'sensitive')
			          AND NOT coalesce((d.body->>'sensitive')::boolean, false)
			          AND (
			              to_tsvector('simple',
			                  coalesce(d.body->>'title', '') || ' ' ||
			                  coalesce(d.body->>'slug', '') || ' ' ||
			                  coalesce(d.body->>'statement', '')) @@ plainto_tsquery('simple', $3)
			              OR coalesce(d.body->>'title', '') ILIKE '%' || $3 || '%'
			          )
			      )
			      OR coalesce(d.body->>'slug', '') ILIKE '%' || $3 || '%'
			  )
			  AND (
			      $4 = ''
			      OR EXISTS (
			          SELECT 1
			          FROM registry.scope_all s
			          JOIN registry.scope_closure_all sc
			            ON sc.tenant_id = s.tenant_id AND sc.descendant_id = s.id
			          WHERE s.tenant_id = d.tenant_id
			            AND s.sys_period @> $1::timestamptz
			            AND sc.sys_period @> $1::timestamptz
			            AND sc.ancestor_id = ANY(d.scope_refs)
			            AND (
			                (s.kind IN ('repo', 'path', 'env') AND s.match_repo = $4)
			                OR (s.kind = 'org' AND s.match_org = split_part($4, '/', 1))
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
			var refsText string
			var upper sql.NullTime
			if err := rows.Scan(&r.ID, &r.Version, &r.Body, &refsText, &r.ValidFrom, &upper); err != nil {
				return err
			}
			refs, err := parseUUIDArray(refsText)
			if err != nil {
				return err
			}
			r.ScopeRefs = refs
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

type scopeCoverage struct {
	orgs         []string
	repoPatterns []repoPattern
	literalRepos []string
}

func (c scopeCoverage) coversRepo(repo string) bool {
	repo = strings.ToLower(strings.TrimSpace(repo))
	if repo == "" {
		return true
	}
	org, _, hasSlash := strings.Cut(repo, "/")
	if slices.Contains(c.orgs, org) {
		return true
	}
	if !hasSlash {
		return false
	}
	segs := strings.Split(repo, "/")
	for _, pat := range c.repoPatterns {
		if pat.matches(segs) {
			return true
		}
	}
	return false
}

func hydrateHealthRows(ctx context.Context, tx *sql.Tx, rows []rawDecisionRow, filterRepo, filterEnv string, validAt, knownAt time.Time) ([]mcptools.DecisionHealth, error) {
	ids := make([]uuid.UUID, len(rows))
	edrIDs := make([]string, 0, len(rows))
	slugs := make([]string, 0, len(rows))
	edrToDecision := make(map[string]uuid.UUID, len(rows))
	slugToDecision := make(map[string]uuid.UUID, len(rows))
	decisionEDRID := make(map[uuid.UUID]string, len(rows))
	decisionSlug := make(map[uuid.UUID]string, len(rows))
	allScopeRefs := make([]uuid.UUID, 0, len(rows))
	seenRef := map[uuid.UUID]bool{}

	for i, r := range rows {
		ids[i] = r.ID
		for _, sref := range r.ScopeRefs {
			if !seenRef[sref] {
				seenRef[sref] = true
				allScopeRefs = append(allScopeRefs, sref)
			}
		}
		var meta struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
		}
		if json.Unmarshal(r.Body, &meta) == nil {
			if meta.ID != "" {
				edrIDs = append(edrIDs, meta.ID)
				edrToDecision[meta.ID] = r.ID
				decisionEDRID[r.ID] = meta.ID
			}
			if meta.Slug != "" {
				slugs = append(slugs, meta.Slug)
				slugToDecision[meta.Slug] = r.ID
				decisionSlug[r.ID] = meta.Slug
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

	coverageByRef := map[uuid.UUID]*scopeCoverage{}
	if len(allScopeRefs) > 0 {
		sRows, err := tx.QueryContext(ctx, `
			SELECT sc.ancestor_id, s.kind, s.match_org, coalesce(s.match_repo, ''), s.repo_key
			FROM registry.scope_closure_all sc
			JOIN registry.scope_all s ON s.tenant_id = sc.tenant_id AND s.id = sc.descendant_id
			WHERE sc.tenant_id = ipso.current_tenant()
			  AND sc.ancestor_id = ANY($1::uuid[])
			  AND sc.sys_period @> $2::timestamptz
			  AND s.sys_period @> $2::timestamptz
			ORDER BY sc.ancestor_id, s.kind, s.selector`, allScopeRefs, knownAt)
		if err != nil {
			return nil, err
		}
		for sRows.Next() {
			var anc uuid.UUID
			var kind, matchOrg, matchRepo, repoKey string
			if err := sRows.Scan(&anc, &kind, &matchOrg, &matchRepo, &repoKey); err != nil {
				_ = sRows.Close()
				return nil, err
			}
			cov := coverageByRef[anc]
			if cov == nil {
				cov = &scopeCoverage{}
				coverageByRef[anc] = cov
			}
			if kind == "org" && matchOrg != "" && !slices.Contains(cov.orgs, matchOrg) {
				cov.orgs = append(cov.orgs, matchOrg)
			}
			if matchRepo != "" {
				if pat, err := parseRepoSelector(matchRepo); err == nil {
					cov.repoPatterns = append(cov.repoPatterns, pat)
				}
				if repoKey != "" && (filterRepo == "" || repoKey == filterRepo) && !slices.Contains(cov.literalRepos, repoKey) {
					cov.literalRepos = append(cov.literalRepos, repoKey)
				}
			}
		}
		_ = sRows.Close()
	}

	coverageByDecision := make(map[uuid.UUID]scopeCoverage, len(rows))
	for _, r := range rows {
		var combined scopeCoverage
		for _, sref := range r.ScopeRefs {
			cov := coverageByRef[sref]
			if cov == nil {
				continue
			}
			for _, o := range cov.orgs {
				if !slices.Contains(combined.orgs, o) {
					combined.orgs = append(combined.orgs, o)
				}
			}
			combined.repoPatterns = append(combined.repoPatterns, cov.repoPatterns...)
			for _, lr := range cov.literalRepos {
				if !slices.Contains(combined.literalRepos, lr) {
					combined.literalRepos = append(combined.literalRepos, lr)
				}
			}
		}
		if filterRepo != "" && len(combined.literalRepos) == 0 && combined.coversRepo(filterRepo) {
			combined.literalRepos = []string{filterRepo}
		}
		coverageByDecision[r.ID] = combined
	}

	supersededBy := map[uuid.UUID]string{}
	supRows, err := tx.QueryContext(ctx, `
		SELECT s.from_decision, s.to_decision::text
		FROM registry.supersession s
		WHERE s.tenant_id = ipso.current_tenant()
		  AND s.from_decision = ANY($1::uuid[])
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

	waiverScopesByDecision := map[uuid.UUID][]uuid.UUID{}
	wRows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT w.decision_id, w.scope_id
		FROM registry.waiver w
		WHERE w.tenant_id = ipso.current_tenant()
		  AND w.decision_id = ANY($1::uuid[])
		  AND w.valid_period @> $2::timestamptz
		  AND w.sys_period @> $3::timestamptz
		  AND EXISTS (
		      SELECT 1
		      FROM registry.decision_version_all d
		      WHERE d.tenant_id = w.tenant_id
		        AND d.decision_id = w.decision_id
		        AND d.valid_period @> $2::timestamptz
		        AND d.sys_period @> $3::timestamptz
		  )`, ids, validAt, knownAt)
	if err != nil {
		return nil, err
	}
	for wRows.Next() {
		var did, sid uuid.UUID
		if err := wRows.Scan(&did, &sid); err != nil {
			_ = wRows.Close()
			return nil, err
		}
		waiverScopesByDecision[did] = append(waiverScopesByDecision[did], sid)
	}
	_ = wRows.Close()

	verdictsByDecision := map[uuid.UUID][]storedVerdictSnap{}
	if len(edrIDs) > 0 || len(slugs) > 0 {
		vRows, err := tx.QueryContext(ctx, `
			SELECT DISTINCT ON (v.decision_id, v.slug, u.repo, u.env, v.check_index, u.source_kind)
			       v.decision_id, v.slug, v.check_index, u.source_kind, u.check_name, u.repo, u.env,
			       v.result, v.violations, u.evaluated_at, coalesce(v.model_id, ''), coalesce(v.prompt_version, '')
			FROM verification.verdict v
			JOIN verification.upload u ON u.tenant_id = v.tenant_id AND u.id = v.upload_id
			WHERE v.tenant_id = ipso.current_tenant()
			  AND u.sys_period @> $1::timestamptz
			  AND ($2 = '' OR u.repo = $2)
			  AND ($3 = '' OR lower(u.env) = lower($3))
			  AND (v.decision_id = ANY($4::text[]) OR v.slug = ANY($5::text[]))
			ORDER BY v.decision_id, v.slug, u.repo, u.env, v.check_index, u.source_kind, u.evaluated_at DESC, v.id DESC`,
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
			var did uuid.UUID
			var matched bool
			if d, ok := edrToDecision[vEDRID]; ok {
				if decisionSlug[d] == "" || vSlug == "" || decisionSlug[d] == vSlug {
					did, matched = d, true
				}
			} else if d, ok := slugToDecision[vSlug]; ok && decisionEDRID[d] == "" {
				did, matched = d, true
			}
			if matched && coverageByDecision[did].coversRepo(snap.Repo) {
				verdictsByDecision[did] = append(verdictsByDecision[did], snap)
			}
		}
		_ = vRows.Close()
	}

	scopesBySubject := map[scopeKey][]uuid.UUID{}
	resolveSubjectScopes := func(repo, env string) ([]uuid.UUID, error) {
		normKey := scopeKey{
			Repo: strings.ToLower(strings.TrimSpace(repo)),
			Env:  strings.ToLower(strings.TrimSpace(env)),
		}
		if normKey.Repo == "" {
			return nil, nil
		}
		if cached, ok := scopesBySubject[normKey]; ok {
			return cached, nil
		}
		subj, err := newWholeSubject(normKey.Repo, normKey.Env)
		if err != nil {
			scopesBySubject[normKey] = nil
			return nil, nil
		}
		sc, err := scopesOf(ctx, tx, subj, knownAt)
		if err != nil {
			return nil, err
		}
		scopesBySubject[normKey] = sc
		return sc, nil
	}

	out := make([]mcptools.DecisionHealth, len(rows))
	for i, r := range rows {
		var isWaived func(repo, env string) bool
		if wScopes := waiverScopesByDecision[r.ID]; len(wScopes) > 0 {
			covered := map[scopeKey]bool{}
			candidates := map[scopeKey]bool{}
			for _, v := range verdictsByDecision[r.ID] {
				candidates[scopeKey{Repo: v.Repo, Env: strings.ToLower(strings.TrimSpace(v.Env))}] = true
			}
			for _, lr := range coverageByDecision[r.ID].literalRepos {
				candidates[scopeKey{Repo: lr, Env: strings.ToLower(strings.TrimSpace(filterEnv))}] = true
			}
			for cand := range candidates {
				sc, err := resolveSubjectScopes(cand.Repo, cand.Env)
				if err != nil {
					return nil, err
				}
				for _, ws := range wScopes {
					if slices.Contains(sc, ws) {
						covered[cand] = true
						break
					}
				}
			}
			isWaived = func(repo, env string) bool {
				return covered[scopeKey{
					Repo: strings.ToLower(strings.TrimSpace(repo)),
					Env:  strings.ToLower(strings.TrimSpace(env)),
				}]
			}
		}
		out[i] = ComputeValidityAndCompliance(
			r.ID,
			r.Body,
			r.ValidFrom,
			r.ValidTo,
			supersededBy[r.ID],
			coverageByDecision[r.ID].literalRepos,
			openPremises[r.ID],
			verdictsByDecision[r.ID],
			isWaived,
			freshness,
			filterEnv,
			validAt,
		)
	}
	return out, nil
}
