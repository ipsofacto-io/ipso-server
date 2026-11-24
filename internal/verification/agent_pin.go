package verification

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	LiveSignatureContext = "ipso-live-verdict-v1"
	MaxLiveSkew          = 5 * time.Minute
)

var (
	pinNameExpr = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)
	ErrUnknownPin = errors.New("unknown agent pin")
)

// AgentPin represents a tenant-registered public key pin for ipso-agent live drift reports (ADR-0162).
type AgentPin struct {
	ID           uuid.UUID `json:"id"`
	Tenant       uuid.UUID `json:"-"`
	Name         string    `json:"name"`
	Repo         string    `json:"repo"`
	Env          string    `json:"env"`
	PinSHA256    string    `json:"pin_sha256"`
	PublicKeyDER []byte    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

// ParseSPKI parses a PEM-encoded or base64-encoded SubjectPublicKeyInfo (ECDSA P-256 or Ed25519)
// and returns its canonical DER encoding and SHA-256 hex pin.
func ParseSPKI(raw string) ([]byte, [32]byte, error) {
	trimmed := strings.TrimSpace(raw)
	var der []byte
	if block, rest := pem.Decode([]byte(trimmed)); block != nil && len(strings.TrimSpace(string(rest))) == 0 {
		if block.Type != "PUBLIC KEY" {
			return nil, [32]byte{}, invalid("public_key must be a PEM PUBLIC KEY")
		}
		der = block.Bytes
	} else {
		var err error
		der, err = base64.StdEncoding.DecodeString(trimmed)
		if err != nil {
			return nil, [32]byte{}, invalid("public_key is not valid PEM or base64 SPKI")
		}
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, [32]byte{}, invalid("public_key is not a valid SubjectPublicKeyInfo")
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, [32]byte{}, invalid("ECDSA public_key must use curve P-256")
		}
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return nil, [32]byte{}, invalid("Ed25519 public_key has invalid length")
		}
	default:
		return nil, [32]byte{}, invalid("public_key must be ECDSA P-256 or Ed25519")
	}
	canonical, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, [32]byte{}, invalid("public_key could not be marshaled")
	}
	return canonical, sha256.Sum256(canonical), nil
}

// LiveMessage builds the domain-separated message signed for POST /v1/verdicts/live.
func LiveMessage(timestampHeader string, body []byte) []byte {
	bodySum := sha256.Sum256(body)
	return []byte(LiveSignatureContext + "\n" + timestampHeader + "\n" + hex.EncodeToString(bodySum[:]))
}

// SignLivePayload signs timestampHeader and body with an ECDSA P-256 or Ed25519 private key.
func SignLivePayload(signer crypto.Signer, timestampHeader string, body []byte) (string, error) {
	msg := LiveMessage(timestampHeader, body)
	switch signer.Public().(type) {
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(msg)
		sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(sig), nil
	case ed25519.PublicKey:
		sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(sig), nil
	default:
		return "", errors.New("unsupported signer key type")
	}
}

// VerifyLivePayload checks the timestamp skew and verifies the detached signature against SPKI DER.
func VerifyLivePayload(spkiDER []byte, timestampHeader, signatureHeader string, body []byte, now time.Time) error {
	if timestampHeader == "" || len(timestampHeader) > 64 || signatureHeader == "" || len(signatureHeader) > 512 {
		return invalid("missing or oversized signature headers")
	}
	ts, err := time.Parse(time.RFC3339, timestampHeader)
	if err != nil {
		return invalid("timestamp is not RFC 3339")
	}
	skew := now.Sub(ts)
	if skew < -MaxLiveSkew || skew > MaxLiveSkew {
		return invalid("timestamp is outside the allowed 5-minute window")
	}
	sig, err := base64.StdEncoding.DecodeString(signatureHeader)
	if err != nil {
		sig, err = base64.RawURLEncoding.DecodeString(signatureHeader)
		if err != nil {
			return invalid("signature is not valid base64")
		}
	}
	pub, err := x509.ParsePKIXPublicKey(spkiDER)
	if err != nil {
		return invalid("stored public key is invalid")
	}
	msg := LiveMessage(timestampHeader, body)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return invalid("unsupported ECDSA curve")
		}
		digest := sha256.Sum256(msg)
		if !ecdsa.VerifyASN1(k, digest[:], sig) {
			return invalid("ECDSA signature verification failed")
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(k, msg, sig) {
			return invalid("Ed25519 signature verification failed")
		}
		return nil
	default:
		return invalid("unsupported public key")
	}
}

// LiveAgentRun derives a deterministic Run record for a signed agent live upload so repeated submissions
// of the same snapshot and timestamp deduplicate cleanly via upload_once.
func LiveAgentRun(pin AgentPin, timestampHeader string, digest []byte) Run {
	h := sha256.Sum256([]byte(pin.PinSHA256 + "\n" + timestampHeader + "\n" + hex.EncodeToString(digest)))
	runID := int64(binary.BigEndian.Uint64(h[:8]) & 0x7fffffffffffffff)
	if runID == 0 {
		runID = 1
	}
	return Run{
		Installation: 0,
		RepositoryID: 0,
		Repo:         strings.ToLower(pin.Repo),
		RunID:        runID,
		RunAttempt:   1,
		SHA:          hex.EncodeToString(h[:20]),
		Ref:          "refs/ipso/live/" + pin.Name,
		Event:        "ipso_agent_live",
		WorkflowRef:  "ipso-agent:" + pin.Name,
	}
}

// RegisterAgentPin stores a new agent public key pin inside caller's READ COMMITTED tenant transaction.
func RegisterAgentPin(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, name, repo, env, rawPublicKey string) (AgentPin, error) {
	name = strings.TrimSpace(name)
	repo = strings.ToLower(strings.TrimSpace(repo))
	env = strings.TrimSpace(env)
	if tenant == uuid.Nil || !pinNameExpr.MatchString(name) || !validRepo(repo) || !plain(env, 0, maxEnvBytes) {
		return AgentPin{}, invalid("invalid agent pin name, repo, or env")
	}
	der, sum, err := ParseSPKI(rawPublicKey)
	if err != nil {
		return AgentPin{}, err
	}
	out := AgentPin{
		Tenant:       tenant,
		Name:         name,
		Repo:         repo,
		Env:          env,
		PinSHA256:    hex.EncodeToString(sum[:]),
		PublicKeyDER: der,
	}
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO verification.agent_pin (tenant_id, name, repo, env, pin_sha256, public_key_der)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, lower(sys_period)`,
		tenant, name, repo, env, sum[:], der).Scan(&out.ID, &out.CreatedAt); err != nil {
		return AgentPin{}, reduce("register agent pin", err)
	}
	return out, nil
}

// ListAgentPins returns the tenant's registered agent public key pins.
func ListAgentPins(ctx context.Context, db *sql.DB, tenant uuid.UUID) ([]AgentPin, error) {
	if db == nil || tenant == uuid.Nil {
		return nil, errors.New("agent pins: database and tenant are required")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, reduce("agent pins: begin", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return nil, reduce("agent pins: set tenant", err)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT id, name, repo, env, encode(pin_sha256, 'hex'), lower(sys_period)
		FROM verification.agent_pin
		WHERE tenant_id = ipso.current_tenant()
		ORDER BY id DESC`)
	if err != nil {
		return nil, reduce("agent pins: read", err)
	}
	defer func() { _ = rows.Close() }()
	pins := []AgentPin{}
	for rows.Next() {
		var p AgentPin
		p.Tenant = tenant
		if err := rows.Scan(&p.ID, &p.Name, &p.Repo, &p.Env, &p.PinSHA256, &p.CreatedAt); err != nil {
			return nil, reduce("agent pins: scan", err)
		}
		pins = append(pins, p)
	}
	return pins, rows.Err()
}

// RevokeAgentPin removes a registered agent pin inside caller's READ COMMITTED tenant transaction.
func RevokeAgentPin(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID) (bool, error) {
	if tenant == uuid.Nil || id == uuid.Nil {
		return false, invalid("tenant and pin id are required")
	}
	res, err := tx.ExecContext(ctx, `
		DELETE FROM verification.agent_pin
		WHERE tenant_id = $1 AND id = $2`, tenant, id)
	if err != nil {
		return false, reduce("revoke agent pin", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// LookupAgentPin resolves a pin_sha256 hex digest for the process's tenant.
func LookupAgentPin(ctx context.Context, db *sql.DB, tenant uuid.UUID, pinHex string) (AgentPin, error) {
	if db == nil || tenant == uuid.Nil || !hexDigits.MatchString(pinHex) {
		return AgentPin{}, ErrUnknownPin
	}
	pinBytes, err := hex.DecodeString(pinHex)
	if err != nil {
		return AgentPin{}, ErrUnknownPin
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AgentPin{}, reduce("lookup agent pin: begin", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return AgentPin{}, reduce("lookup agent pin: set tenant", err)
	}
	var out AgentPin
	out.Tenant = tenant
	out.PinSHA256 = pinHex
	err = tx.QueryRowContext(ctx, `
		SELECT id, name, repo, env, public_key_der, lower(sys_period)
		FROM verification.agent_pin
		WHERE tenant_id = ipso.current_tenant() AND pin_sha256 = $1`, pinBytes).Scan(
		&out.ID, &out.Name, &out.Repo, &out.Env, &out.PublicKeyDER, &out.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AgentPin{}, ErrUnknownPin
	}
	if err != nil {
		return AgentPin{}, reduce("lookup agent pin: scan", err)
	}
	return out, nil
}
