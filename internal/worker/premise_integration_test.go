//go:build integration

package worker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
	"github.com/ipsofacto-io/ipso/pkg/premisecheck"
)

const premiseHost = "status.example.com"

var premiseDecision = uuid.MustParse("00000000-0000-4000-8000-0000000000d1")

// premiseAt is a recordable premise that expects {"major": equals} at path on host.
func premiseAt(id, host, path string, equals int) string {
	return fmt.Sprintf(`{"id":%q,"statement":"s","every":7,"probe":{"url":"https://%s%s","pointer":"/major","equals":%d}}`,
		id, host, path, equals)
}

func premiseFor(id, path string, equals int) string { return premiseAt(id, premiseHost, path, equals) }

// premiseSite is an HTTPS server for premiseHost, and the client that reaches it whatever address the name
// resolves to. It records each request it receives.
type premiseSite struct {
	mu   sync.Mutex
	seen []seenRequest
	pool *x509.CertPool
	srv  *httptest.Server
}

type seenRequest struct {
	path   string
	header http.Header
}

func (p *premiseSite) requests(path string) []seenRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []seenRequest
	for _, r := range p.seen {
		if r.path == path {
			out = append(out, r)
		}
	}
	return out
}

func (p *premiseSite) total() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.seen)
}

func (p *premiseSite) client() premisecheck.Client {
	return premisecheck.Client{
		Roots: p.pool,
		Lookup: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		},
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, p.srv.Listener.Addr().String())
		},
	}
}

func newPremiseSite(t *testing.T) *premiseSite {
	t.Helper()
	site := &premiseSite{}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{premiseHost},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	site.pool = x509.NewCertPool()
	site.pool.AddCert(leaf)
	site.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		site.mu.Lock()
		site.seen = append(site.seen, seenRequest{path: r.URL.Path, header: r.Header.Clone()})
		site.mu.Unlock()
		if r.URL.Path == "/moved" {
			http.Redirect(w, r, "/platform.json", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(`{"major":16}`))
	}))
	site.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}, MinVersion: tls.VersionTLS12}
	site.srv.StartTLS()
	t.Cleanup(site.srv.Close)
	return site
}

// premises adds a decision in force whose body carries the premises, as the application role.
func (s *stack) premises(t *testing.T, tenant, decision uuid.UUID, premises ...string) {
	t.Helper()
	ctx, id := t.Context(), tenant.String()
	var scope uuid.UUID
	if err := pgtest.Scan(ctx, s.app, id, `
		INSERT INTO registry.scope (tenant_id, kind, selector) VALUES ($1, 'org', $2) RETURNING id`,
		[]any{tenant, "premises-" + decision.String()}, &scope); err != nil {
		t.Fatal(err)
	}
	if _, err := pgtest.Exec(ctx, s.app, id, `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1, 1, $2, $3::jsonb, ARRAY[$4::uuid], '[2000-01-01,)'::tstzrange)`,
		decision, tenant, `{"premises":[`+strings.Join(premises, ",")+`]}`, scope); err != nil {
		t.Fatal(err)
	}
}

func (s *stack) allow(t *testing.T, tenant uuid.UUID, host string, allowed bool) {
	t.Helper()
	if _, err := pgtest.Exec(t.Context(), s.app, tenant.String(),
		`INSERT INTO registry.premise_host_allow (tenant_id, host, allowed) VALUES ($1, $2, $3)`, tenant, host, allowed); err != nil {
		t.Fatal(err)
	}
}

func (s *stack) count(t *testing.T, tenant uuid.UUID, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pgtest.Scan(t.Context(), s.app, tenant.String(), query, args, &n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (s *stack) result(t *testing.T, tenant uuid.UUID, premise string) string {
	t.Helper()
	var result string
	err := pgtest.Scan(t.Context(), s.app, tenant.String(),
		`SELECT result FROM registry.premise_evaluation WHERE premise_id = $1 ORDER BY lower(sys_period) DESC, id DESC LIMIT 1`,
		[]any{premise}, &result)
	if err != nil {
		return ""
	}
	return result
}

func (s *stack) evaluations(t *testing.T, tenant uuid.UUID) int {
	t.Helper()
	return s.count(t, tenant, `SELECT count(*) FROM registry.premise_evaluation`)
}

func (s *stack) decisionRow(t *testing.T) string {
	t.Helper()
	admin := s.database.Open(t, pgtest.Admin)
	var row string
	if err := admin.QueryRowContext(t.Context(), `
		SELECT version || '|' || body::text || '|' || valid_period::text || '|' || sys_period::text
		FROM registry.decision_version WHERE decision_id = $1`, premiseDecision).Scan(&row); err != nil {
		t.Fatal(err)
	}
	return row
}

// Two workers run the sweep and the probes. A due premise on an allowed host is probed once, a pass opens no
// reason, a fail opens one, the decision is left as it was, and nothing is probed again until it is due.
func TestADuePremiseIsProbedOnceByTwoWorkersAndAFailOpensOneReason(t *testing.T) {
	s := newStack(t)
	site := newPremiseSite(t)
	s.premises(t, tenantA, premiseDecision, premiseFor("holds", "/platform.json", 16), premiseFor("fails", "/platform.json", 15))
	s.allow(t, tenantA, premiseHost, true)
	before := s.decisionRow(t)

	stopFirst := s.startProbing(t, tenantA, site.client())
	stopSecond := s.startProbing(t, tenantA, site.client())

	eventually(t, "both premises were evaluated", func() bool { return s.evaluations(t, tenantA) >= 2 })
	eventually(t, "a sweep completed", func() bool { return s.jobs(t, `kind = 'premise_sweep' AND state = 'completed'`) >= 1 })
	eventually(t, "the probes completed", func() bool { return s.jobs(t, `kind = 'premise_probe' AND state = 'completed'`) >= 2 })

	if n := s.evaluations(t, tenantA); n != 2 {
		t.Errorf("evaluations with two workers = %d, want one for each premise", n)
	}
	if got := s.result(t, tenantA, "holds"); got != "pass" {
		t.Errorf("holds = %q, want pass", got)
	}
	if got := s.result(t, tenantA, "fails"); got != "fail" {
		t.Errorf("fails = %q, want fail", got)
	}
	if n := s.count(t, tenantA, `SELECT count(*) FROM registry.premise_reason WHERE premise_id = 'fails'`); n != 1 {
		t.Errorf("reasons for the fail = %d, want 1", n)
	}
	if n := s.count(t, tenantA, `SELECT count(*) FROM registry.premise_reason WHERE premise_id = 'holds'`); n != 0 {
		t.Errorf("reasons for the pass = %d, want 0", n)
	}
	if after := s.decisionRow(t); after != before {
		t.Errorf("the decision changed:\n before %s\n after  %s", before, after)
	}
	for _, r := range site.requests("/platform.json") {
		if r.header.Get("Authorization") != "" || r.header.Get("Cookie") != "" {
			t.Errorf("the worker sent credentials: %v", r.header)
		}
		if r.header.Get("User-Agent") != "ipso-premise" {
			t.Errorf("user agent = %q", r.header.Get("User-Agent"))
		}
	}

	// A restart sweeps again and finds nothing due, since each latest evaluation is new.
	stopFirst()
	stopSecond()
	done := s.jobs(t, `kind = 'premise_sweep' AND state = 'completed'`)
	hits := site.total()
	s.startProbing(t, tenantA, site.client())
	eventually(t, "a sweep ran after the restart", func() bool {
		return s.jobs(t, `kind = 'premise_sweep' AND state = 'completed'`) > done
	})
	if n := s.evaluations(t, tenantA); n != 2 || site.total() != hits {
		t.Errorf("evaluations = %d, requests %d -> %d: a premise that was not due was probed", n, hits, site.total())
	}
}

// An empty allowlist and a revoked host are errors. The worker makes no request for either, and opens no
// reason.
func TestAnEmptyAllowlistAndARevokedHostRecordAnErrorAndOpenNoReason(t *testing.T) {
	s := newStack(t)
	site := newPremiseSite(t)
	const revoked = "revoked.example.com"
	s.premises(t, tenantA, premiseDecision,
		premiseFor("not-listed", "/platform.json", 15),
		premiseAt("revoked", revoked, "/platform.json", 15))
	s.allow(t, tenantA, revoked, true)
	s.allow(t, tenantA, revoked, false)
	s.startProbing(t, tenantA, site.client())

	eventually(t, "a host with no allowlist row was recorded as an error", func() bool { return s.result(t, tenantA, "not-listed") == "error" })
	eventually(t, "the revoked host was recorded as an error", func() bool { return s.result(t, tenantA, "revoked") == "error" })
	if site.total() != 0 {
		t.Errorf("the worker made %d requests for hosts that are not allowed", site.total())
	}
	if n := s.count(t, tenantA, `SELECT count(*) FROM registry.premise_reason`); n != 0 {
		t.Errorf("reasons = %d, want none for an error", n)
	}
}

func TestARedirectIsAnErrorAndIsNotFollowed(t *testing.T) {
	s := newStack(t)
	site := newPremiseSite(t)
	s.premises(t, tenantA, premiseDecision, premiseFor("moved", "/moved", 16))
	s.allow(t, tenantA, premiseHost, true)
	s.startProbing(t, tenantA, site.client())

	eventually(t, "the redirect was recorded as an error", func() bool { return s.result(t, tenantA, "moved") == "error" })
	if n := len(site.requests("/moved")); n != 1 {
		t.Errorf("requests to the redirecting path = %d, want 1", n)
	}
	if n := len(site.requests("/platform.json")); n != 0 {
		t.Errorf("the worker followed the redirect %d times", n)
	}
	if n := s.count(t, tenantA, `SELECT count(*) FROM registry.premise_reason`); n != 0 {
		t.Errorf("reasons = %d, want none for an error", n)
	}
}

// The tenant nobody serves has a due premise and an allowed host, and nothing is probed for it.
func TestThePremisesOfTheTenantNobodyServesAreLeftAlone(t *testing.T) {
	s := newStack(t)
	site := newPremiseSite(t)
	s.premises(t, tenantB, premiseDecision, premiseFor("holds", "/platform.json", 16))
	s.allow(t, tenantB, premiseHost, true)
	s.startProbing(t, tenantA, site.client())

	eventually(t, "a sweep completed", func() bool { return s.jobs(t, `kind = 'premise_sweep' AND state = 'completed'`) >= 1 })
	if n := s.evaluations(t, tenantB); n != 0 || site.total() != 0 {
		t.Errorf("evaluations of the other tenant = %d, requests = %d", n, site.total())
	}
}
