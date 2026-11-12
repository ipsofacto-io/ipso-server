//go:build compose

// Package compose holds the smoke test of the local stack (compose.yaml, ADR-0095). ci / compose
// starts the stack and runs it against the published ports. It reads the test-only values of
// .env.example from the environment and trusts the stack's throwaway CA from IPSO_SMOKE_CA.
package compose

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
)

const (
	defaultAPI = "http://127.0.0.1:8080"
	defaultDex = "https://localhost:5556"
	// startupTime is how long the stack may take to answer after `docker compose up`.
	startupTime = 3 * time.Minute
)

func setting(t *testing.T, name, fallback string) string {
	t.Helper()
	if value := os.Getenv(name); value != "" {
		return value
	}
	if fallback == "" {
		t.Fatalf("%s is not set", name)
	}
	return fallback
}

// dexClient trusts only the CA the stack made.
func dexClient(t *testing.T) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(setting(t, "IPSO_SMOKE_CA", ""))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("IPSO_SMOKE_CA holds no certificate")
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
}

// token asks Dex for an access token with the password grant, as the client named.
func token(t *testing.T, client *http.Client, clientID, secretEnv string) string {
	t.Helper()
	form := url.Values{
		"grant_type":    {"password"},
		"scope":         {"openid"},
		"username":      {setting(t, "IPSO_DEX_USER", "")},
		"password":      {setting(t, "IPSO_DEX_PASSWORD", "")},
		"client_id":     {clientID},
		"client_secret": {setting(t, secretEnv, "")},
	}
	endpoint := setting(t, "IPSO_SMOKE_DEX", defaultDex) + "/dex/token"
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var answer struct {
		AccessToken string `json:"access_token"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &answer) != nil || answer.AccessToken == "" {
		// The answer of a failed grant names the problem and holds no token.
		t.Fatalf("token for %s: status %d: %s", clientID, resp.StatusCode, body)
	}
	return answer.AccessToken
}

// client has a deadline, so a stalled front fails a request and not the whole job.
var client = &http.Client{Timeout: 15 * time.Second}

// try returns an error and never calls t.FailNow, so it is safe in a goroutine of its own.
func try(ctx context.Context, base, method, path, bearer string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, base+path, nil)
	if err != nil {
		return 0, "", err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(body), nil
}

func call(t *testing.T, method, path, bearer string) (int, string) {
	t.Helper()
	status, body, err := try(t.Context(), setting(t, "IPSO_SMOKE_API", defaultAPI), method, path, bearer)
	if err != nil {
		t.Fatal(err)
	}
	return status, body
}

// bearerCall is call with a JSON body, and with the whole answer: an archive is far over what call keeps.
func bearerCall(t *testing.T, method, path, bearer, body string) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, setting(t, "IPSO_SMOKE_API", defaultAPI)+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, answer
}

func waitForHealth(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), startupTime)
	defer cancel()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, setting(t, "IPSO_SMOKE_API", defaultAPI)+"/healthz", nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp, err := client.Do(req); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusNoContent {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("the API did not answer its health check within %s", startupTime)
		case <-time.After(2 * time.Second):
		}
	}
}

func TestTheStackServesTheAPIToItsTestUserOnly(t *testing.T) {
	waitForHealth(t)
	dex := dexClient(t)
	good := token(t, dex, "ipso-api", "IPSO_API_CLIENT_SECRET")
	other := token(t, dex, "other-app", "IPSO_OTHER_CLIENT_SECRET")

	t.Run("a token for the API client reads the registry", func(t *testing.T) {
		for _, path := range []string{"/v1/scopes", "/v1/decisions"} {
			if status, body := call(t, http.MethodGet, path, good); status != http.StatusOK {
				t.Errorf("GET %s: status %d: %s", path, status, body)
			}
		}
	})
	t.Run("no token is refused", func(t *testing.T) {
		if status, _ := call(t, http.MethodGet, "/v1/scopes", ""); status != http.StatusUnauthorized {
			t.Errorf("status %d, want 401", status)
		}
	})
	t.Run("a token minted for another client is refused", func(t *testing.T) {
		if status, _ := call(t, http.MethodGet, "/v1/scopes", other); status != http.StatusUnauthorized {
			t.Errorf("status %d, want 401", status)
		}
	})
	t.Run("a tenant in the query is refused", func(t *testing.T) {
		if status, _ := call(t, http.MethodGet, "/v1/scopes?tenant=00000000-0000-4000-8000-0000000000ff", good); status != http.StatusBadRequest {
			t.Errorf("status %d, want 400", status)
		}
	})
	t.Run("an admin exports the tenant and opens the archive with the key it gave", func(t *testing.T) {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		status, body := bearerCall(t, http.MethodPost, "/v1/exports", good, `{"recipient":"`+identity.Recipient().String()+`"}`)
		var export struct {
			ID    string `json:"id"`
			State string `json:"state"`
		}
		if status != http.StatusAccepted || json.Unmarshal(body, &export) != nil || export.ID == "" {
			t.Fatalf("POST /v1/exports: status %d: %s", status, body)
		}
		// The worker finds the request with its sweep, which runs every minute.
		deadline := time.Now().Add(3 * time.Minute)
		for export.State != "ready" {
			if time.Now().After(deadline) {
				t.Fatalf("the export was still %s after 3 minutes", export.State)
			}
			time.Sleep(2 * time.Second)
			status, body = bearerCall(t, http.MethodGet, "/v1/exports/"+export.ID, good, "")
			if status != http.StatusOK || json.Unmarshal(body, &export) != nil || export.State == "failed" {
				t.Fatalf("GET /v1/exports/%s: status %d: %s", export.ID, status, body)
			}
		}
		status, archive := bearerCall(t, http.MethodGet, "/v1/exports/"+export.ID+"/archive", good, "")
		if status != http.StatusOK {
			t.Fatalf("the archive: status %d", status)
		}
		plain, err := age.Decrypt(strings.NewReader(string(archive)), identity)
		if err != nil {
			t.Fatalf("the holder of the key cannot open the archive: %v", err)
		}
		zr, err := gzip.NewReader(plain)
		if err != nil {
			t.Fatal(err)
		}
		first, err := bufio.NewReader(zr).ReadString('\n')
		if err != nil || !strings.Contains(first, `"format":"ipso-tenant-export/2"`) || !strings.Contains(first, setting(t, "IPSO_TENANT_ID", "")) {
			t.Fatalf("the header is %q (%v)", first, err)
		}
	})
	// Last, because it empties the front's bucket for this address.
	t.Run("the front limits a client that has no token", func(t *testing.T) {
		api := setting(t, "IPSO_SMOKE_API", defaultAPI)
		var mu sync.Mutex
		limited, reached := 0, 0
		var wg sync.WaitGroup
		for range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 20 {
					status, body, err := try(t.Context(), api, http.MethodGet, "/v1/scopes", "")
					mu.Lock()
					if err != nil {
						t.Errorf("a request failed: %v", err)
						mu.Unlock()
						return
					}
					switch status {
					case http.StatusTooManyRequests:
						limited++
						if !strings.Contains(body, "rate_limited") {
							t.Errorf("a limited answer is %q", body)
						}
					case http.StatusUnauthorized:
						reached++
					}
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if limited == 0 {
			t.Errorf("400 requests without a token were all answered by the API (%d)", reached)
		}
		if reached == 0 {
			t.Error("the front refused every request, so the burst did not reach the API at all")
		}
	})
}
