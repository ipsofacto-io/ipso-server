// Package mcpremote serves the MCP tools over Streamable HTTP as an OAuth 2.1 resource server
// (ADR-0077). The tool contract and the JSON-RPC layer come from ipso's pkg/mcptools, so a client
// sees what the local server offers. The binary does not mount this handler: it needs a tenant from
// the authenticated token, and no deployment may serve a tenant before row-level security (ADR-0050).
package mcpremote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso/pkg/mcptools"
)

// Scopes a token can hold. Reading and proposing are separate, so a client can ask for the least.
const (
	ScopeRead    = "ipso.read"
	ScopePropose = "ipso.propose"
)

const (
	metadataPrefix = "/.well-known/oauth-protected-resource"
	// maxBodyBytes bounds one request. A plan or a diff is evaluated on the client's machine, so a
	// request here is only ever a small tool call.
	maxBodyBytes = 1 << 20

	codeParse              = -32700
	codeInvalidRequest     = -32600
	codeHeaderMismatch     = -32020
	codeUnsupportedVersion = -32022
)

// Claims is what a verified token says.
type Claims struct {
	Subject  string
	ClientID string
	Scopes   []string
}

// Verifier checks a bearer token. JWTVerifier is the implementation.
type Verifier interface {
	Verify(ctx context.Context, raw string) (Claims, error)
}

// Caller is who a verified token speaks for. A nil tenant or principal is refused.
type Caller struct {
	Tenant    uuid.UUID
	Principal uuid.UUID
}

// CallerFunc maps verified claims to a caller. The mapping belongs to the login work (IPSO-65). The
// tenant comes from here and never from the request. A false result is 403.
type CallerFunc func(context.Context, Claims) (Caller, bool)

// BackendFunc returns the tools for one caller.
type BackendFunc func(Caller) mcptools.Backend

// Config describes this resource. ResourceURL is the canonical URL of the MCP endpoint (RFC 8707)
// and must be https, or http on a loopback address for a test.
type Config struct {
	ResourceURL          string
	AuthorizationServers []string
	Version              string
}

type handler struct {
	cfg         Config
	resource    *url.URL
	metadataURL string
	verifier    Verifier
	callers     CallerFunc
	backends    BackendFunc
}

// NewHandler returns the MCP endpoint and its Protected Resource Metadata (RFC 9728).
func NewHandler(cfg Config, verifier Verifier, callers CallerFunc, backends BackendFunc) (http.Handler, error) {
	resource, err := url.Parse(cfg.ResourceURL)
	if err != nil {
		return nil, fmt.Errorf("the resource URL: %w", err)
	}
	if resource.Host == "" || resource.Fragment != "" || resource.RawQuery != "" || resource.Path == "" || resource.Path == "/" {
		return nil, errors.New("the resource URL must name a host and a path, with no query or fragment")
	}
	if resource.Scheme != "https" && (resource.Scheme != "http" || !isLoopback(resource.Hostname())) {
		return nil, errors.New("the resource URL must be https, or http on a loopback address")
	}
	if len(cfg.AuthorizationServers) == 0 {
		return nil, errors.New("at least one authorization server is required")
	}
	if verifier == nil || callers == nil || backends == nil {
		return nil, errors.New("a verifier, a caller function, and a backend function are required")
	}
	h := &handler{
		cfg:         cfg,
		resource:    resource,
		metadataURL: resource.Scheme + "://" + resource.Host + metadataPrefix + resource.Path,
		verifier:    verifier,
		callers:     callers,
		backends:    backends,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+metadataPrefix+resource.Path, h.metadata)
	mux.HandleFunc("POST "+resource.Path, h.post)
	// 2026-07-28 removes the GET stream, and there are no sessions to delete.
	notAllowed := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", http.MethodPost)
		writeFailure(w, http.StatusMethodNotAllowed, "use POST")
	}
	mux.HandleFunc("GET "+resource.Path, notAllowed)
	mux.HandleFunc("DELETE "+resource.Path, notAllowed)
	return mux, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (h *handler) metadata(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource":                 h.cfg.ResourceURL,
		"authorization_servers":    h.cfg.AuthorizationServers,
		"scopes_supported":         []string{ScopeRead, ScopePropose},
		"bearer_methods_supported": []string{"header"},
	})
}

type rpcRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		Name string `json:"name"`
		Meta struct {
			ProtocolVersion string `json:"io.modelcontextprotocol/protocolVersion"`
		} `json:"_meta"`
	} `json:"params"`
}

// post checks the request in the order that reveals least: where it came from, who sent it, and only
// then what it says. The body is not read for a caller who has not proved anything.
func (h *handler) post(w http.ResponseWriter, r *http.Request) {
	if !h.originAllowed(r) {
		writeFailure(w, http.StatusForbidden, "this origin is not allowed")
		return
	}
	claims, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	caller, ok := h.callers(r.Context(), claims)
	if !ok || caller.Tenant == uuid.Nil || caller.Principal == uuid.Nil {
		writeFailure(w, http.StatusForbidden, "this token speaks for no principal here")
		return
	}
	mediaType, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	if !strings.EqualFold(strings.TrimSpace(mediaType), "application/json") {
		writeFailure(w, http.StatusUnsupportedMediaType, "send application/json")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeFailure(w, http.StatusRequestEntityTooLarge, "the request is too large")
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPCError(w, http.StatusBadRequest, nil, codeParse, "parse error")
		return
	}
	if code, message := checkHeaders(r, req); code != 0 {
		writeRPCError(w, http.StatusBadRequest, req.ID, code, message)
		return
	}
	if scope := requiredScope(req); scope != "" && !slices.Contains(claims.Scopes, scope) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_scope", scope=%q, resource_metadata=%q`, scope, h.metadataURL))
		writeFailure(w, http.StatusForbidden, "this token lacks the scope "+scope)
		return
	}
	server := mcptools.NewServer(h.cfg.Version, h.backends(caller))
	reply := server.Handle(r.Context(), body)
	if reply == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if rpcErrorCode(reply) == codeUnsupportedVersion || rpcErrorCode(reply) == codeInvalidRequest {
		w.WriteHeader(http.StatusBadRequest)
	}
	_, _ = w.Write(reply)
}

func rpcErrorCode(reply []byte) int {
	var parsed struct {
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(reply, &parsed); err != nil {
		return 0
	}
	return parsed.Error.Code
}

// originAllowed is the DNS rebinding guard. The Host must be this resource's host, and an Origin, when
// a browser sends one, must be this resource.
func (h *handler) originAllowed(r *http.Request) bool {
	if !strings.EqualFold(r.Host, h.resource.Host) {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	return strings.EqualFold(origin, h.resource.Scheme+"://"+h.resource.Host)
}

// authenticate answers 401 with where to get a token. The header form is the only one accepted, so a
// token cannot end up in a URL or a log.
func (h *handler) authenticate(w http.ResponseWriter, r *http.Request) (Claims, bool) {
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata=%q, scope=%q`, h.metadataURL, ScopeRead))
		writeFailure(w, http.StatusUnauthorized, "a bearer token is required")
		return Claims{}, false
	}
	claims, err := h.verifier.Verify(r.Context(), token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="invalid_token", resource_metadata=%q`, h.metadataURL))
		writeFailure(w, http.StatusUnauthorized, "the token is not valid")
		return Claims{}, false
	}
	return claims, true
}

// checkHeaders applies the 2026-07-28 transport rules. A client on an older revision sends none of
// these headers, so it is left alone.
func checkHeaders(r *http.Request, req rpcRequest) (int, string) {
	version := r.Header.Get("MCP-Protocol-Version")
	meta := req.Params.Meta.ProtocolVersion
	if version != "" && !slices.Contains(mcptools.SupportedVersions(), version) {
		return codeUnsupportedVersion, "unsupported protocol version"
	}
	if version != "" && meta != "" && version != meta {
		return codeHeaderMismatch, "MCP-Protocol-Version does not match the request"
	}
	if version != mcptools.LatestVersion && meta != mcptools.LatestVersion {
		return 0, ""
	}
	if version == "" {
		return codeHeaderMismatch, "MCP-Protocol-Version is required"
	}
	if trimOWS(r.Header.Get("Mcp-Method")) != req.Method {
		return codeHeaderMismatch, "Mcp-Method does not match the request"
	}
	if req.Method == "tools/call" && trimOWS(r.Header.Get("Mcp-Name")) != req.Params.Name {
		return codeHeaderMismatch, "Mcp-Name does not match the request"
	}
	return 0, ""
}

func trimOWS(value string) string {
	return strings.Trim(value, " \t")
}

// requiredScope is the least a request needs. Learning what the server offers needs only a valid token.
func requiredScope(req rpcRequest) string {
	switch req.Method {
	case "tools/list":
		return ScopeRead
	case "tools/call":
		if req.Params.Name == mcptools.ToolPropose {
			return ScopePropose
		}
		return ScopeRead
	default:
		return ""
	}
}

func writeFailure(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func writeRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, message string) {
	if len(bytes.TrimSpace(id)) == 0 {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}})
}
