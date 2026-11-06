package tenancy

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func testKEK(t *testing.T, fill byte) (KEK, string) {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, keySize))
	kek, err := ParseKEK(encoded)
	if err != nil {
		t.Fatalf("ParseKEK: %v", err)
	}
	return kek, encoded
}

func TestParseKEKRefusesWhatIsNotA32ByteKey(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, keySize-1))
	long := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, keySize+1))
	zero := base64.StdEncoding.EncodeToString(make([]byte, keySize))
	urlSafe := strings.NewReplacer("+", "-", "/", "_").Replace(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, keySize)))
	for name, value := range map[string]string{
		"empty":     "",
		"not b64":   "not base64 at all!",
		"too short": short,
		"too long":  long,
		"all zero":  zero,
		"url-safe":  urlSafe,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseKEK(value)
			if !errors.Is(err, ErrKey) {
				t.Fatalf("ParseKEK(%q) = %v, want ErrKey", value, err)
			}
			if value != "" && strings.Contains(err.Error(), value) {
				t.Fatalf("the error quotes the value: %v", err)
			}
		})
	}
}

func TestWrapAndUnwrapRoundTripForOneTenantOnly(t *testing.T) {
	kek, _ := testKEK(t, 7)
	tenant, other := uuid.New(), uuid.New()
	dek, err := newDataKey()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := kek.Wrap(tenant, dek)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapped) != wrappedSize {
		t.Fatalf("wrapped key is %d bytes, the CHECK on tenancy.tenant_key says %d", len(wrapped), wrappedSize)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("the data key appears in the wrapped bytes")
	}
	got, err := kek.Unwrap(tenant, wrapped)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("Unwrap = %x, %v; want the data key", got, err)
	}
	if _, err := kek.Unwrap(other, wrapped); !errors.Is(err, ErrKey) {
		t.Fatalf("another tenant opened the key: %v", err)
	}
	otherKEK, _ := testKEK(t, 9)
	if _, err := otherKEK.Unwrap(tenant, wrapped); !errors.Is(err, ErrKey) {
		t.Fatalf("another key encryption key opened the key: %v", err)
	}
	for i := range wrapped {
		flipped := bytes.Clone(wrapped)
		flipped[i] ^= 1
		if _, err := kek.Unwrap(tenant, flipped); !errors.Is(err, ErrKey) {
			t.Fatalf("byte %d changed and the key still opened: %v", i, err)
		}
	}
	if _, err := kek.Unwrap(tenant, wrapped[:wrappedSize-1]); !errors.Is(err, ErrKey) {
		t.Fatalf("a short wrapped key opened: %v", err)
	}
}

func TestWrapUsesAFreshNonceAndRefusesABadKey(t *testing.T) {
	kek, _ := testKEK(t, 7)
	tenant := uuid.New()
	dek := bytes.Repeat([]byte{1}, keySize)
	a, _ := kek.Wrap(tenant, dek)
	b, _ := kek.Wrap(tenant, dek)
	if bytes.Equal(a, b) {
		t.Fatal("two wraps of one key are identical, so the nonce is reused")
	}
	if _, err := kek.Wrap(tenant, dek[:keySize-1]); !errors.Is(err, ErrKey) {
		t.Fatalf("a short data key was wrapped: %v", err)
	}
	var zero KEK
	if _, err := zero.Wrap(tenant, dek); !errors.Is(err, ErrKey) {
		t.Fatalf("the zero KEK wrapped a key: %v", err)
	}
	if _, err := zero.Unwrap(tenant, a); !errors.Is(err, ErrKey) {
		t.Fatalf("the zero KEK unwrapped a key: %v", err)
	}
}

func TestNewDataKeyIsRandom(t *testing.T) {
	a, err := newDataKey()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := newDataKey()
	if len(a) != keySize || bytes.Equal(a, b) {
		t.Fatalf("data keys %x and %x", a, b)
	}
}
