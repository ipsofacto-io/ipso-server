package tenancy

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestParseRecipientReadsOneNativeOrHybridPublicKey(t *testing.T) {
	native, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]string{"native": native.Recipient().String(), "hybrid": hybrid.Recipient().String()} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseRecipient(key)
			if err != nil || got == nil {
				t.Fatalf("ParseRecipient(%s key) = %v, %v", name, got, err)
			}
			// The key it returns encrypts to the holder of the private key, and to nobody else.
			var archive bytes.Buffer
			w, err := age.Encrypt(&archive, got)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(w, "synthetic")
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			var identity age.Identity = native
			if name == "hybrid" {
				identity = hybrid
			}
			r, err := age.Decrypt(&archive, identity)
			if err != nil {
				t.Fatalf("the holder of the private key cannot open it: %v", err)
			}
			if text, _ := io.ReadAll(r); string(text) != "synthetic" {
				t.Fatalf("opened %q", text)
			}
		})
	}
}

func TestParseRecipientRefusesAnythingElseWithoutQuotingIt(t *testing.T) {
	native, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	key := native.Recipient().String()
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"empty":                    "",
		"a private key":            native.String(),
		"a word":                   "hunter2",
		"the prefix alone":         "age1",
		"a key with a bad letter":  key[:len(key)-1] + "b",
		"a key cut short":          key[:len(key)-4],
		"a key in upper case":      strings.ToUpper(key),
		"a key with a space":       key + " ",
		"a key with a newline":     key + "\n",
		"two keys":                 key + "\n" + other.Recipient().String(),
		"a comment":                "# " + key,
		"a plugin recipient":       "age1yubikey1qdoesnotexist",
		"an ssh key":               "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ",
		"a hybrid prefix, no body": "age1pq1",
		"a very long key":          "age1" + strings.Repeat("q", maxRecipient),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseRecipient(value)
			if err == nil || got != nil || !errors.Is(err, ErrBadRecipient) {
				t.Fatalf("ParseRecipient = %v, %v, want ErrBadRecipient", got, err)
			}
			if value != "" && strings.Contains(err.Error(), value) {
				t.Fatalf("the error quotes the value: %v", err)
			}
		})
	}
}

// parts is what a partWriter handed to its store.
type parts struct {
	data [][]byte
	err  error
}

func (p *parts) put(seq int, data []byte) error {
	if p.err != nil {
		return p.err
	}
	if seq != len(p.data) {
		return fmt.Errorf("part %d out of order, want %d", seq, len(p.data))
	}
	// The writer reuses its buffer, so a store that keeps a part has to copy it.
	p.data = append(p.data, bytes.Clone(data))
	return nil
}

func TestThePartWriterCutsTheArchiveIntoPartsOfOneMebibyteAndKeepsItsSum(t *testing.T) {
	archive := make([]byte, 2*ExportPartSize+12345)
	for i := range archive {
		archive[i] = byte(i * 7)
	}
	for name, chunk := range map[string]int{"one write": len(archive), "odd writes": 99991, "tiny writes": 4099, "part sized writes": ExportPartSize} {
		t.Run(name, func(t *testing.T) {
			store := &parts{}
			w := newPartWriter(store.put)
			for rest := archive; len(rest) > 0; {
				n := min(chunk, len(rest))
				if got, err := w.Write(rest[:n]); err != nil || got != n {
					t.Fatalf("Write = %d, %v", got, err)
				}
				rest = rest[n:]
			}
			if err := w.flush(); err != nil {
				t.Fatal(err)
			}
			if len(store.data) != 3 || len(store.data[0]) != ExportPartSize || len(store.data[1]) != ExportPartSize || len(store.data[2]) != 12345 {
				t.Fatalf("parts of sizes %d, want 1 MiB, 1 MiB and 12345", len(store.data))
			}
			if !bytes.Equal(bytes.Join(store.data, nil), archive) {
				t.Fatal("the parts are not the archive")
			}
			if w.total != int64(len(archive)) || w.seq != 3 {
				t.Errorf("total %d in %d parts", w.total, w.seq)
			}
			if want := sha256.Sum256(archive); !bytes.Equal(w.hash.Sum(nil), want[:]) {
				t.Error("the sum is not the SHA-256 of the archive")
			}
		})
	}
}

func TestThePartWriterStoresNothingForNothingAndOnePartForAnExactMultiple(t *testing.T) {
	store := &parts{}
	w := newPartWriter(store.put)
	if err := w.flush(); err != nil || len(store.data) != 0 {
		t.Fatalf("an empty flush stored %d parts (%v)", len(store.data), err)
	}
	if _, err := w.Write(make([]byte, ExportPartSize)); err != nil {
		t.Fatal(err)
	}
	if err := w.flush(); err != nil || len(store.data) != 1 {
		t.Fatalf("an exact part left %d parts (%v), want 1", len(store.data), err)
	}
}

func TestThePartWriterStopsAtTheFirstFailedPartAndAtTheCap(t *testing.T) {
	boom := errors.New("the store refused a part")
	store := &parts{err: boom}
	w := newPartWriter(store.put)
	if _, err := w.Write(make([]byte, ExportPartSize+1)); !errors.Is(err, boom) {
		t.Fatalf("Write = %v, want the store's error", err)
	}

	store = &parts{}
	w = newPartWriter(store.put)
	w.total = MaxStoredExport - 10
	if _, err := w.Write(make([]byte, 10)); err != nil {
		t.Fatalf("a write up to the cap = %v", err)
	}
	if _, err := w.Write(make([]byte, 1)); !errors.Is(err, ErrExportTooLarge) {
		t.Fatalf("a write past the cap = %v, want ErrExportTooLarge", err)
	}
}
