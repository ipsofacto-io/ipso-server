// Package integrations holds the source-control connectors. Today that is the GitHub App of
// ADR-0061: a verified webhook, a token scoped to one repository and one job, and a check run
// with annotations on the decision files of a change.
package integrations

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"time"
)

const (
	apiBase       = "https://api.github.com"
	apiVersion    = "2022-11-28"
	apiTimeout    = 30 * time.Second
	maxAPIBody    = 8 << 20
	jwtLifetime   = 9 * time.Minute
	jwtClockSkew  = 60 * time.Second
	readAccess    = "read"
	writeAccess   = "write"
	acceptJSON    = "application/vnd.github+json"
	acceptRawFile = "application/vnd.github.raw+json"
)

// appPermissions is the permission set of section 3.1. Verify refuses an App with any other.
var appPermissions = map[string]string{
	"checks":        writeAccess,
	"contents":      readAccess,
	"metadata":      readAccess,
	"pull_requests": writeAccess,
}

// appEvents are the webhook events the App may subscribe to.
var appEvents = []string{"pull_request", "push"}

// ErrNotFound is a 404 from the API.
var ErrNotFound = errors.New("github: not found")

// App authenticates as one GitHub App. key is a crypto.Signer so that a key held in a KMS can
// replace the in-memory key without another change here.
type App struct {
	id     string
	key    crypto.Signer
	base   string
	client *http.Client
	now    func() time.Time
}

// NewApp parses an RSA private key in PEM form, PKCS#1 or PKCS#8.
func NewApp(appID string, privateKeyPEM []byte) (*App, error) {
	if _, err := strconv.ParseInt(appID, 10, 64); err != nil {
		return nil, errors.New("the app id is not a number")
	}
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("the private key is not PEM")
	}
	var key *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = parsed
	} else if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("the private key is not RSA")
		}
		key = rsaKey
	} else {
		return nil, errors.New("the private key cannot be parsed")
	}
	return &App{
		id:   appID,
		key:  key,
		base: apiBase,
		client: &http.Client{
			Timeout: apiTimeout,
			// A token must reach only the API host. A renamed repository fails instead of following.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now: time.Now,
	}, nil
}

// jwt signs the short token that authenticates as the App itself.
func (a *App) jwt() (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	now := a.now()
	claims, err := json.Marshal(map[string]any{
		"iat": now.Add(-jwtClockSkew).Unix(),
		"exp": now.Add(jwtLifetime).Unix(),
		"iss": a.id,
	})
	if err != nil {
		return "", err
	}
	encoding := base64.RawURLEncoding
	signed := encoding.EncodeToString(header) + "." + encoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signed))
	signature, err := a.key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("sign the app token: %w", err)
	}
	return signed + "." + encoding.EncodeToString(signature), nil
}

// Verify reads the registered App and refuses one whose permissions are not exactly section 3.1,
// or that subscribes to an event outside appEvents. A setting changed in the GitHub UI then
// stops the service at its next start instead of widening what it can do.
func (a *App) Verify(ctx context.Context) error {
	token, err := a.jwt()
	if err != nil {
		return err
	}
	var app struct {
		Permissions map[string]string `json:"permissions"`
		Events      []string          `json:"events"`
	}
	if err := a.call(ctx, token, http.MethodGet, "/app", nil, &app); err != nil {
		return fmt.Errorf("read the app: %w", err)
	}
	if !maps.Equal(app.Permissions, appPermissions) {
		return errors.New("the app permissions are not the set in section 3.1")
	}
	for _, event := range app.Events {
		if !slices.Contains(appEvents, event) {
			return errors.New("the app subscribes to an event this service does not handle")
		}
	}
	return nil
}

// repoClient mints a token limited to one repository and to perms, which must be a subset of
// appPermissions. The answer has to confirm that limit, or the token is not used.
func (a *App) repoClient(ctx context.Context, installationID, repoID int64, repo string, perms map[string]string) (*RepoClient, error) {
	token, err := a.jwt()
	if err != nil {
		return nil, err
	}
	request := map[string]any{"repository_ids": []int64{repoID}, "permissions": perms}
	var answer struct {
		Token       string            `json:"token"`
		Permissions map[string]string `json:"permissions"`
	}
	path := "/app/installations/" + strconv.FormatInt(installationID, 10) + "/access_tokens"
	if err := a.call(ctx, token, http.MethodPost, path, request, &answer); err != nil {
		return nil, fmt.Errorf("mint a token: %w", err)
	}
	if answer.Token == "" {
		return nil, errors.New("mint a token: empty answer")
	}
	for name, level := range answer.Permissions {
		if perms[name] != level {
			return nil, errors.New("mint a token: the answer grants more than the request")
		}
	}
	return &RepoClient{app: a, token: answer.Token, repo: repo}, nil
}

// call sends one JSON request. An error names the status and never the response body or a token.
func (a *App) call(ctx context.Context, token, method, path string, body, out any) error {
	raw, err := a.do(ctx, token, method, path, acceptJSON, body)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return errors.New("github: the answer is not the expected JSON")
	}
	return nil
}

func (a *App) do(ctx context.Context, token, method, path, accept string, body any) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, a.base+path, reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", accept)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-GitHub-Api-Version", apiVersion)
	request.Header.Set("User-Agent", "ipso-server")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := a.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("github: %s failed", method)
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxAPIBody+1))
	if err != nil {
		return nil, errors.New("github: reading the answer failed")
	}
	switch {
	case response.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case response.StatusCode < 200 || response.StatusCode > 299:
		return nil, fmt.Errorf("github: status %d", response.StatusCode)
	case len(raw) > maxAPIBody:
		return nil, errors.New("github: the answer is too large")
	}
	return raw, nil
}
