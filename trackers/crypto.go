// Package trackers stores tracker bindings, pending proposals, and link status (ADR-0133).
// Vendor HTTP lives in ipso-ee. This package seals credentials and writes rows.
package trackers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	Jira           = "jira"
	Linear         = "linear"
	GitHubIssues   = "github_issues"
	StatusOpen     = "open"
	StatusDone     = "done"
	StatusCanceled = "canceled"
	defaultLabel   = "ipso-decision"
)

// ErrInvalid, ErrConflict, and ErrNotFound are the closed failures of this package.
var (
	ErrInvalid  = errors.New("invalid tracker")
	ErrConflict = errors.New("tracker conflict")
	ErrNotFound = errors.New("tracker not found")
)

// KnownConnector reports whether connector is one of the three paid trackers.
func KnownConnector(connector string) bool {
	switch connector {
	case Jira, Linear, GitHubIssues:
		return true
	default:
		return false
	}
}

// KnownStatus reports whether status is one of the link values.
func KnownStatus(status string) bool {
	switch status {
	case StatusOpen, StatusDone, StatusCanceled:
		return true
	default:
		return false
	}
}

// ParseKey decodes IPSO_CONNECTOR_KEK. The value is the base64 of 32 bytes.
func ParseKey(raw string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("%w: the connector key must be the base64 of 32 bytes", ErrInvalid)
	}
	return key, nil
}

// Seal encrypts plaintext with AES-256-GCM. Additional data is the tenant and the connector,
// so a ciphertext cannot be moved to another binding. The result is the nonce, then the
// ciphertext and tag.
func Seal(key []byte, tenant uuid.UUID, connector, plaintext string) ([]byte, error) {
	if len(key) != 32 || tenant == uuid.Nil || !KnownConnector(connector) || plaintext == "" || len(plaintext) > 4000 {
		return nil, ErrInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalid
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalid
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, []byte(plaintext), additionalData(tenant, connector)), nil
}

// Open reverses Seal. A wrong key, tenant, or connector is ErrInvalid.
func Open(key, sealed []byte, tenant uuid.UUID, connector string) (string, error) {
	if len(key) != 32 || tenant == uuid.Nil || !KnownConnector(connector) || len(sealed) < 29 || len(sealed) > 8192 {
		return "", ErrInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", ErrInvalid
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrInvalid
	}
	if len(sealed) < gcm.NonceSize() {
		return "", ErrInvalid
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, additionalData(tenant, connector))
	if err != nil {
		return "", ErrInvalid
	}
	return string(plain), nil
}

func additionalData(tenant uuid.UUID, connector string) []byte {
	return []byte(tenant.String() + "\n" + connector)
}

func plainText(value string, max int) bool {
	if value == "" || strings.TrimSpace(value) != value || utf8.RuneCountInString(value) > max {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
