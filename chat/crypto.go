// Package chat stores outbound Slack and Teams destinations and the delivery ledger (ADR-0138).
// Vendor HTTP lives in ipso-ee. This package seals webhook URLs and writes rows.
package chat

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	Slack       = "slack"
	Teams       = "teams"
	KindWaiver  = "waiver"
	KindPremise = "premise"
	// LineLimit is the most lines one digest posts. The rest wait for the next run.
	LineLimit = 20
	maxURL    = 2048
)

// ErrInvalid, ErrConflict, and ErrNotFound are the closed failures of this package.
var (
	ErrInvalid  = errors.New("invalid chat destination")
	ErrConflict = errors.New("chat destination conflict")
	ErrNotFound = errors.New("chat destination not found")
)

// KnownConnector reports whether connector is Slack or Teams.
func KnownConnector(connector string) bool {
	switch connector {
	case Slack, Teams:
		return true
	default:
		return false
	}
}

// KnownKind reports whether kind is a waiver digest or a premise digest.
func KnownKind(kind string) bool {
	switch kind {
	case KindWaiver, KindPremise:
		return true
	default:
		return false
	}
}

// Seal encrypts the webhook URL with AES-256-GCM. Additional data is the tenant and the connector,
// so a ciphertext cannot be moved to another destination. The result is the nonce, then the
// ciphertext and tag.
func Seal(key []byte, tenant uuid.UUID, connector, plaintext string) ([]byte, error) {
	if len(key) != 32 || tenant == uuid.Nil || !KnownConnector(connector) || !plainText(plaintext, maxURL) {
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
	if !plainText(string(plain), maxURL) {
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
