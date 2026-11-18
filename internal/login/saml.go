package login

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"github.com/ipsofacto-io/ipso-server/eehooks"
)

// postedLogin is a provider whose callback is a cross-site POST, not the authorization-code GET.
type postedLogin interface {
	redirect(requestID string) string
	completePOST(ctx context.Context, body []byte, requestID string) (subject, error)
	metadata() []byte
	idpIssuer() string
}

type samlProvider struct {
	login eehooks.BrowserLogin
}

func newSAML(login eehooks.BrowserLogin) provider {
	return samlProvider{login: login}
}

func (p samlProvider) authorizeURL(_, state, _, _ string) string {
	return p.login.RedirectURL(state)
}

func (p samlProvider) complete(context.Context, string, string, string, string) (subject, error) {
	return subject{}, &failure{phase: "saml", code: "post"}
}

func (p samlProvider) issuerParameter() (string, bool) { return "", false }

func (p samlProvider) redirect(requestID string) string {
	return p.login.RedirectURL(requestID)
}

func (p samlProvider) completePOST(ctx context.Context, body []byte, requestID string) (subject, error) {
	issuer, sub, err := p.login.Subject(ctx, body, requestID)
	if err != nil || issuer == "" || sub == "" {
		return subject{}, &failure{phase: "saml"}
	}
	return subject{issuer: issuer, subject: sub}, nil
}

func (p samlProvider) metadata() []byte { return p.login.Metadata() }

func (p samlProvider) idpIssuer() string { return p.login.Issuer() }

// xmlRequestID is an XML NCName. Base64 can start with a digit, which an ID must not.
func xmlRequestID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "_" + hex.EncodeToString(raw), nil
}
