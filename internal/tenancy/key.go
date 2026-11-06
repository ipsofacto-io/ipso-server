package tenancy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

const (
	// keySize is the size of the key encryption key and of a tenant's data key.
	keySize = 32
	// wrappedSize is a 12 byte nonce, the 32 byte data key, and the 16 byte GCM tag. The CHECK on
	// tenancy.tenant_key says the same.
	wrappedSize = 12 + keySize + 16
	// wrapContext binds a wrapped key to its purpose and format version.
	wrapContext = "ipso-tenant-dek/1:"
)

// ErrKey is returned when a key encryption key is malformed or a wrapped key does not open with it.
var ErrKey = errors.New("tenant key")

// KEK is the key encryption key of a deployment. It wraps the data key of each tenant and is never
// stored in the database (ADR-0100). IPSO-64 replaces it with a key in a cloud KMS for each tenant.
type KEK struct {
	aead cipher.AEAD
}

// ParseKEK reads a key encryption key from standard base64 of exactly 32 bytes. The error never quotes
// the value.
func ParseKEK(encoded string) (KEK, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return KEK{}, fmt.Errorf("%w: the key encryption key is not standard base64", ErrKey)
	}
	defer clear(raw)
	if len(raw) != keySize {
		return KEK{}, fmt.Errorf("%w: the key encryption key must be %d bytes", ErrKey, keySize)
	}
	var zero [keySize]byte
	if subtle.ConstantTimeCompare(raw, zero[:]) == 1 {
		return KEK{}, fmt.Errorf("%w: the key encryption key is all zero", ErrKey)
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return KEK{}, fmt.Errorf("%w: the key encryption key is not usable", ErrKey)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return KEK{}, fmt.Errorf("%w: the key encryption key is not usable", ErrKey)
	}
	return KEK{aead: aead}, nil
}

// newDataKey returns a fresh random data key.
func newDataKey() ([]byte, error) {
	dek := make([]byte, keySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("%w: read random bytes", ErrKey)
	}
	return dek, nil
}

// additionalData ties a wrapped key to one tenant, so a row copied to another tenant does not open.
func additionalData(tenant uuid.UUID) []byte {
	return append([]byte(wrapContext), tenant[:]...)
}

// Wrap seals a data key for a tenant with AES-256-GCM and a fresh nonce, and returns nonce then
// ciphertext.
func (k KEK) Wrap(tenant uuid.UUID, dek []byte) ([]byte, error) {
	if k.aead == nil {
		return nil, fmt.Errorf("%w: no key encryption key", ErrKey)
	}
	if len(dek) != keySize {
		return nil, fmt.Errorf("%w: a data key must be %d bytes", ErrKey, keySize)
	}
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("%w: read random bytes", ErrKey)
	}
	return k.aead.Seal(nonce, nonce, dek, additionalData(tenant)), nil
}

// Unwrap opens a wrapped key. It fails for another tenant, another key encryption key, or a changed
// byte.
func (k KEK) Unwrap(tenant uuid.UUID, wrapped []byte) ([]byte, error) {
	if k.aead == nil {
		return nil, fmt.Errorf("%w: no key encryption key", ErrKey)
	}
	if len(wrapped) != wrappedSize {
		return nil, fmt.Errorf("%w: a wrapped key must be %d bytes", ErrKey, wrappedSize)
	}
	nonce, sealed := wrapped[:k.aead.NonceSize()], wrapped[k.aead.NonceSize():]
	dek, err := k.aead.Open(nil, nonce, sealed, additionalData(tenant))
	if err != nil {
		return nil, fmt.Errorf("%w: the wrapped key does not open", ErrKey)
	}
	return dek, nil
}
