package registry

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

// The writes of the control plane API (IPSO-134, ADR-0109). Each takes the transaction of the caller, which
// is READ COMMITTED with ipso.tenant set for that transaction only, because the scope, supersession and reason
// triggers refuse a repeatable read transaction. The tenant must be the authenticated one, because a write
// trusts it. A write checks what the database would also check, so that a bad value is a client error and
// not a constraint name, and it leaves every rule that depends on other rows to the triggers, whose refusal
// the caller maps to a conflict.

// ErrNotFound is returned by a write when an id it names is not a row of the tenant.
var ErrNotFound = errors.New("not found")

// ErrBodyTooLarge is returned when the text form of a decision body is over 1 MiB, the limit the database
// holds (ADR-0051). The request limit is on the JSON the client sent, which can be smaller: the stored
// text adds a space after each comma and colon and writes 1e2000 in full.
var ErrBodyTooLarge = errors.New("the decision body is too large")

// MaxBodyText is the largest text form of a decision body.
const MaxBodyText = 1 << 20

const (
	maxFingerprints = 100000
	maxPremises     = 20
	maxReason       = 2000
	maxLabel        = 200
	maxTitle        = 300
	maxSlug         = 128
	maxWaiver       = 90 * 24 * time.Hour
)

var (
	scopeKinds = []string{"org", "domain", "service", "repo", "path", "env"}
	// kebabExpr is the id of a premise and the slug of a decision: lowercase words joined by hyphens.
	kebabExpr = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	// hostExpr is the premise_host_allow_host constraint of migration 00006.
	hostExpr    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	numericHost = regexp.MustCompile(`^[0-9.]+$`)
	// fingerprintExpr is the encoding of ADR-0059: 64 lowercase hexadecimal characters.
	fingerprintExpr = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidQuery}, args...)...)
}

// checkText holds the rule of the text columns of a waiver: 1 to max characters, trimmed, no control
// character.
func checkText(name, s string, max int) error {
	if n := utf8.RuneCountInString(s); n < 1 || n > max || strings.TrimSpace(s) != s || !utf8.ValidString(s) {
		return invalid("%s must be 1 to %d characters with no space at either end", name, max)
	}
	if strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return invalid("%s holds a control character", name)
	}
	return nil
}

func finite(name string, t time.Time) error {
	if t.IsZero() || t.Year() < 1 || t.Year() > 9999 {
		return invalid("%s must be a date", name)
	}
	return nil
}

// decisionsExist reports whether the tenant has a row for every decision named. A missing one is ErrNotFound.
func decisionsExist(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, ids ...uuid.UUID) error {
	unique := UniqueIDs(ids)
	var found int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(DISTINCT decision_id)
		FROM registry.decision_version
		WHERE tenant_id = $1 AND decision_id = ANY($2::uuid[])`, tenant, unique).Scan(&found); err != nil {
		return fmt.Errorf("read the decisions: %w", err)
	}
	if found != len(unique) {
		return ErrNotFound
	}
	return nil
}

func scopeKind(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID) (string, error) {
	var kind string
	err := tx.QueryRowContext(ctx, `SELECT kind FROM registry.scope WHERE tenant_id = $1 AND id = $2`, tenant, id).Scan(&kind)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read the scope: %w", err)
	}
	return kind, nil
}

// NewScope is a scope to create. ParentID is nil for an org and set for every other kind.
type NewScope struct {
	ParentID *uuid.UUID
	Kind     string
	Selector string
}

// CreateScope adds a node to the scope tree (ADR-0051). A scope is insert-only, so a typo is corrected by
// retiring the node and creating another. The trigger refuses a parent of a kind the node cannot sit under.
func CreateScope(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, in NewScope) (Scope, error) {
	if !slices.Contains(scopeKinds, in.Kind) {
		return Scope{}, invalid("the kind of a scope is one of %s", strings.Join(scopeKinds, ", "))
	}
	if (in.Kind == "org") != (in.ParentID == nil) {
		return Scope{}, invalid("an org has no parent and every other kind has one")
	}
	var err error
	switch in.Kind {
	case "repo":
		_, err = parseRepoSelector(in.Selector)
	case "path":
		_, err = parsePathSelector(in.Selector)
	default:
		err = validateName(in.Selector)
	}
	if err != nil {
		return Scope{}, invalid("the selector does not fit a %s", in.Kind)
	}
	if in.ParentID != nil {
		if _, err := scopeKind(ctx, tx, tenant, *in.ParentID); err != nil {
			return Scope{}, err
		}
	}
	out := Scope{ParentID: in.ParentID, Kind: in.Kind, Selector: in.Selector}
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO registry.scope (tenant_id, parent_id, kind, selector)
		VALUES ($1, $2, $3, $4)
		RETURNING id`, tenant, in.ParentID, in.Kind, in.Selector).Scan(&out.ID); err != nil {
		return Scope{}, fmt.Errorf("create the scope: %w", err)
	}
	return out, nil
}

// ReparentScope moves a node under another parent (ADR-0056). The trigger refuses a move under the node
// itself or one of its descendants, a parent of a kind the node cannot sit under, and a repo whose owner
// is not the org above the new parent. The node keeps its id, so every decision and waiver that names it
// follows.
func ReparentScope(ctx context.Context, tx *sql.Tx, tenant, id, parent uuid.UUID) (Scope, error) {
	if id == uuid.Nil || parent == uuid.Nil {
		return Scope{}, invalid("a scope and a parent are required")
	}
	if _, err := scopeKind(ctx, tx, tenant, parent); err != nil {
		return Scope{}, err
	}
	out := Scope{}
	var parentID uuid.UUID
	err := tx.QueryRowContext(ctx, `
		UPDATE registry.scope SET parent_id = $3
		WHERE tenant_id = $1 AND id = $2
		RETURNING id, parent_id, kind, selector`, tenant, id, parent).Scan(&out.ID, &parentID, &out.Kind, &out.Selector)
	if errors.Is(err, sql.ErrNoRows) {
		return Scope{}, ErrNotFound
	}
	if err != nil {
		return Scope{}, fmt.Errorf("move the scope: %w", err)
	}
	out.ParentID = &parentID
	return out, nil
}

// RetireScope removes a node from the tree (ADR-0056). The trigger refuses a node that still has a child,
// and the foreign key of a role binding refuses a node that is still bound.
func RetireScope(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID) error {
	if id == uuid.Nil {
		return invalid("a scope is required")
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM registry.scope WHERE tenant_id = $1 AND id = $2`, tenant, id)
	if err != nil {
		return fmt.Errorf("retire the scope: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("retire the scope: %w", err)
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordSupersession makes the decision to replace the decision from at the instant effective (ADR-0052).
// The insert closes the old decision in the same transaction. The trigger refuses an instant the two
// decisions do not both span, a decision that is already superseded, and a second successor.
func RecordSupersession(ctx context.Context, tx *sql.Tx, tenant, from, to uuid.UUID, effective time.Time) (uuid.UUID, error) {
	if from == uuid.Nil || to == uuid.Nil || from == to {
		return uuid.Nil, invalid("two different decisions are required")
	}
	if err := finite("effective_at", effective); err != nil {
		return uuid.Nil, err
	}
	if err := decisionsExist(ctx, tx, tenant, from, to); err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO registry.supersession (tenant_id, from_decision, to_decision, effective_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id`, tenant, from, to, effective).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("record the supersession: %w", err)
	}
	return id, nil
}

// RecordGrandfatherPeriod gives a decision a period during which what already violates it is tolerated
// (ADR-0052). Until is nil for a period with no deadline, which is a baseline. There is one period for
// each decision, ever.
func RecordGrandfatherPeriod(ctx context.Context, tx *sql.Tx, tenant, decision uuid.UUID, from time.Time, until *time.Time) error {
	if decision == uuid.Nil {
		return invalid("a decision is required")
	}
	if err := finite("valid_from", from); err != nil {
		return err
	}
	if until != nil {
		if err := finite("valid_until", *until); err != nil {
			return err
		}
		if !until.After(from) {
			return invalid("valid_until must be after valid_from")
		}
	}
	if err := decisionsExist(ctx, tx, tenant, decision); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO registry.grandfather_period (tenant_id, decision_id, valid_period)
		VALUES ($1, $2, tstzrange($3, $4, '[)'))`, tenant, decision, from, until); err != nil {
		return fmt.Errorf("record the grandfather period: %w", err)
	}
	return nil
}

// RecordBaseline stores the fingerprints of the violations of a decision that already exist in one
// repository (ADR-0052, ADR-0059). A fingerprint is 64 lowercase hexadecimal characters, a digest and
// never a path or a message. A baseline needs the grandfather period of its decision first, through the
// foreign key, and there is one for each decision and repository.
func RecordBaseline(ctx context.Context, tx *sql.Tx, tenant, decision uuid.UUID, repo string, fingerprints []string) (uuid.UUID, error) {
	if decision == uuid.Nil {
		return uuid.Nil, invalid("a decision is required")
	}
	if !literalRepoOK(repo) {
		return uuid.Nil, invalid("repo must be a lowercase owner/name")
	}
	if len(fingerprints) < 1 || len(fingerprints) > maxFingerprints {
		return uuid.Nil, invalid("a baseline holds 1 to %d fingerprints", maxFingerprints)
	}
	raw := make([][]byte, 0, len(fingerprints))
	seen := make(map[string]struct{}, len(fingerprints))
	for _, f := range fingerprints {
		if !fingerprintExpr.MatchString(f) {
			return uuid.Nil, invalid("a fingerprint is 64 lowercase hexadecimal characters")
		}
		if _, dup := seen[f]; dup {
			return uuid.Nil, invalid("a fingerprint appears twice")
		}
		seen[f] = struct{}{}
		b, err := hex.DecodeString(f)
		if err != nil {
			return uuid.Nil, invalid("a fingerprint is 64 lowercase hexadecimal characters")
		}
		raw = append(raw, b)
	}
	if err := decisionsExist(ctx, tx, tenant, decision); err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO registry.baseline (tenant_id, decision_id, repo, fingerprints)
		VALUES ($1, $2, $3, $4::bytea[])
		RETURNING id`, tenant, decision, repo, raw).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("record the baseline: %w", err)
	}
	return id, nil
}

// NewWaiver is a waiver to record. The approver is not a field: RecordWaiver takes it from the principal.
type NewWaiver struct {
	DecisionID uuid.UUID
	ScopeID    uuid.UUID
	Reason     string
	TicketRef  string
	ValidFrom  time.Time
	ExpiresAt  time.Time
}

// RecordWaiver records a waiver (ADR-0054). The approver is the person in approver, whose name the record
// shows, and the trigger refuses an approver that is not a person. The period is half open and at most 90
// days, and the triggers refuse one that a current row of the decision does not contain, and a scope that
// is not on or under the decision's scopes.
func RecordWaiver(ctx context.Context, tx *sql.Tx, tenant, approver uuid.UUID, in NewWaiver) (Waiver, error) {
	if in.DecisionID == uuid.Nil || in.ScopeID == uuid.Nil || approver == uuid.Nil {
		return Waiver{}, invalid("a decision and a scope are required")
	}
	if err := checkText("reason", in.Reason, maxReason); err != nil {
		return Waiver{}, err
	}
	if err := checkText("ticket_ref", in.TicketRef, maxLabel); err != nil {
		return Waiver{}, err
	}
	if err := finite("valid_from", in.ValidFrom); err != nil {
		return Waiver{}, err
	}
	if err := finite("expires_at", in.ExpiresAt); err != nil {
		return Waiver{}, err
	}
	if !in.ExpiresAt.After(in.ValidFrom) || in.ExpiresAt.Sub(in.ValidFrom) > maxWaiver {
		return Waiver{}, invalid("a waiver lasts more than zero and at most 90 days")
	}
	if err := decisionsExist(ctx, tx, tenant, in.DecisionID); err != nil {
		return Waiver{}, err
	}
	if _, err := scopeKind(ctx, tx, tenant, in.ScopeID); err != nil {
		return Waiver{}, err
	}
	out := Waiver{DecisionID: in.DecisionID, ScopeID: in.ScopeID, TicketRef: in.TicketRef, ValidFrom: in.ValidFrom, ExpiresAt: in.ExpiresAt}
	err := tx.QueryRowContext(ctx, `
		INSERT INTO registry.waiver (tenant_id, decision_id, scope_id, reason, approver, approver_id, valid_period, ticket_ref)
		SELECT $1, $2, $3, $4, p.name, p.id, tstzrange($5, $6, '[)'), $7
		FROM identity.principal p
		WHERE p.tenant_id = $1 AND p.id = $8
		RETURNING id`, tenant, in.DecisionID, in.ScopeID, in.Reason, in.ValidFrom, in.ExpiresAt, in.TicketRef, approver).Scan(&out.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return Waiver{}, ErrNotFound
	}
	if err != nil {
		return Waiver{}, fmt.Errorf("record the waiver: %w", err)
	}
	return out, nil
}

// ClearPremiseReason closes the open review reason of a premise with a human clearance (ADR-0053). It does
// not change the decision: the reason asked an owner to look, and the clearance says one did. A premise
// with no open reason is ErrNotFound. The row names no person, so the action log is the record of who did.
func ClearPremiseReason(ctx context.Context, tx *sql.Tx, tenant, decision uuid.UUID, premise string) (uuid.UUID, error) {
	if decision == uuid.Nil {
		return uuid.Nil, invalid("a decision is required")
	}
	if !kebabExpr.MatchString(premise) || len(premise) > maxSlug {
		return uuid.Nil, invalid("a premise id is lowercase words joined by hyphens")
	}
	var id uuid.UUID
	err := tx.QueryRowContext(ctx, `
		INSERT INTO registry.premise_clearance (tenant_id, reason_id, kind)
		SELECT r.tenant_id, r.id, 'human'
		FROM registry.premise_reason r
		WHERE r.tenant_id = $1 AND r.decision_id = $2 AND r.premise_id = $3
		  AND NOT EXISTS (
		      SELECT 1 FROM registry.premise_clearance c
		      WHERE c.tenant_id = r.tenant_id AND c.reason_id = r.id)
		RETURNING id`, tenant, decision, premise).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("clear the review reason: %w", err)
	}
	return id, nil
}

// AllowPremiseHost appends a row to the allowlist of the hosts a premise probe may dial (ADR-0053). The
// latest row for a host decides, so allowed false withdraws a host. A host is a lowercase DNS name in ASCII,
// written in punycode when it is not, and never an address (ADR-0098).
func AllowPremiseHost(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, host string, allowed bool) (uuid.UUID, error) {
	host = strings.ToLower(host)
	if len(host) < 1 || len(host) > 253 || !hostExpr.MatchString(host) || numericHost.MatchString(host) {
		return uuid.Nil, invalid("host must be a DNS name in lowercase ASCII, in punycode when it is not")
	}
	var id uuid.UUID
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO registry.premise_host_allow (tenant_id, host, allowed)
		VALUES ($1, $2, $3)
		RETURNING id`, tenant, host, allowed).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("write the allowlist: %w", err)
	}
	return id, nil
}

// DecisionScopes reads the scopes the decisions name, which is what a call on them needs the role policy
// to cover: the union of scope_refs over every current row of each, whatever its valid period. It also
// counts the decisions the tenant has no row for, because a call on a decision that is not there is covered
// by nothing but a binding over the whole tenant. The tenant must be the authenticated one.
func DecisionScopes(ctx context.Context, db *sql.DB, tenant uuid.UUID, decisions []uuid.UUID) (scopes []uuid.UUID, missing int, err error) {
	if tenant == uuid.Nil || len(decisions) == 0 {
		return nil, 0, fmt.Errorf("%w: a tenant and a decision are required", ErrInvalidQuery)
	}
	unique := UniqueIDs(decisions)
	found := make(map[uuid.UUID]struct{}, len(unique))
	seen := make(map[uuid.UUID]struct{})
	err = readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT d.decision_id, s
			FROM registry.decision_version d
			CROSS JOIN LATERAL unnest(d.scope_refs) AS s
			WHERE d.tenant_id = ipso.current_tenant() AND d.decision_id = ANY($1::uuid[])`, unique)
		if err != nil {
			return fmt.Errorf("read the scopes of the decisions: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var decision, scope uuid.UUID
			if err := rows.Scan(&decision, &scope); err != nil {
				return fmt.Errorf("read the scopes of the decisions: %w", err)
			}
			found[decision] = struct{}{}
			if _, dup := seen[scope]; !dup {
				seen[scope] = struct{}{}
				scopes = append(scopes, scope)
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	return scopes, len(unique) - len(found), nil
}

// NewDecision is the first version of a decision, written when a person approves a proposal.
type NewDecision struct {
	Body      json.RawMessage
	ScopeRefs []uuid.UUID
	ValidFrom time.Time
}

// InsertDecision writes version 1 of a new decision, valid from the instant given with no end, and returns
// its id. It is the only code that inserts a decision version: a version is written only through the
// approval by a person of a proposal (ADR-0076), so proposals.Approve is its only caller. The body is a
// JSON object with a slug and a title and at most 20 premises, each of which the premise sweep can probe
// (ADR-0098). Its text form is at most 1 MiB, and a body over that is ErrBodyTooLarge and is not stored.
func InsertDecision(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, in NewDecision) (uuid.UUID, error) {
	var body struct {
		Slug     string          `json:"slug"`
		Title    string          `json:"title"`
		Premises json.RawMessage `json:"premises"`
	}
	if err := json.Unmarshal(in.Body, &body); err != nil || len(in.Body) == 0 || in.Body[0] != '{' {
		return uuid.Nil, invalid("the decision is a JSON object")
	}
	if !kebabExpr.MatchString(body.Slug) || len(body.Slug) > maxSlug {
		return uuid.Nil, invalid("the slug of a decision is lowercase words joined by hyphens")
	}
	if n := utf8.RuneCountInString(body.Title); n < 1 || n > maxTitle || strings.TrimSpace(body.Title) != body.Title {
		return uuid.Nil, invalid("the title of a decision is 1 to %d characters", maxTitle)
	}
	if len(body.Premises) > 0 && string(body.Premises) != "null" {
		var premises []json.RawMessage
		if err := json.Unmarshal(body.Premises, &premises); err != nil || len(premises) > maxPremises {
			return uuid.Nil, invalid("premises is a list of at most %d", maxPremises)
		}
	}
	if len(in.ScopeRefs) < 1 || len(in.ScopeRefs) > 100 || slices.Contains(in.ScopeRefs, uuid.Nil) {
		return uuid.Nil, invalid("a decision names 1 to 100 scopes")
	}
	if err := finite("valid_from", in.ValidFrom); err != nil {
		return uuid.Nil, err
	}
	var size int
	if err := tx.QueryRowContext(ctx, `SELECT octet_length($1::jsonb::text)`, string(in.Body)).Scan(&size); err != nil {
		return uuid.Nil, invalid("the decision is not JSON")
	}
	if size > MaxBodyText {
		return uuid.Nil, ErrBodyTooLarge
	}
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("make a decision id: %w", err)
	}
	refs := UniqueIDs(in.ScopeRefs)
	var known int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM registry.scope WHERE tenant_id = $1 AND id = ANY($2::uuid[])`,
		tenant, refs).Scan(&known); err != nil {
		return uuid.Nil, fmt.Errorf("read the scopes: %w", err)
	}
	if known != len(refs) {
		return uuid.Nil, invalid("a scope of the decision is not a scope of the tenant")
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1, 1, $2, $3::jsonb, $4::uuid[], tstzrange($5, NULL, '[)'))`,
		id, tenant, string(in.Body), in.ScopeRefs, in.ValidFrom); err != nil {
		return uuid.Nil, fmt.Errorf("write the decision: %w", err)
	}
	var unrecordable int
	if err := tx.QueryRowContext(ctx, unrecordablePremises, id).Scan(&unrecordable); err != nil {
		return uuid.Nil, fmt.Errorf("check the premises: %w", err)
	}
	if unrecordable > 0 {
		return uuid.Nil, invalid("a premise cannot be probed: check its id, interval, url, pointer and comparison")
	}
	return id, nil
}

// UniqueIDs returns the ids sorted and once each, without changing the list given.
func UniqueIDs(ids []uuid.UUID) []uuid.UUID {
	out := slices.Clone(ids)
	slices.SortFunc(out, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	return slices.Compact(out)
}

// unrecordablePremises counts the premises of a decision that the sweep would leave alone, with the
// expression the sweep uses (ADR-0098). It reads the rows of the decision whatever their valid period,
// since the version it checks may not be in force yet.
const unrecordablePremises = `
WITH items AS (
    SELECT d.tenant_id, d.decision_id, p.item
    FROM registry.decision_version d
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(d.body -> 'premises') = 'array' THEN d.body -> 'premises' ELSE '[]'::jsonb END
    ) AS p(item)
    WHERE d.tenant_id = ipso.current_tenant() AND d.decision_id = $1` + premiseRecordable + `
)
SELECT count(*) FROM recordable WHERE NOT recordable`
