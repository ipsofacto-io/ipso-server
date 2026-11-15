package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// LogFormat names the hashed form of an entry of the action log and the form of a line of its export
// (ADR-0126). A change to either is a new version.
const LogFormat = "ipso-audit-log/1"

// LogPageSize is the most entries one LogPage reads.
const LogPageSize = 1000

// The reasons a chain is broken, in the order a check tests them.
const (
	// BreakGap means the position of an entry is not the one after the entry before it, so an entry is
	// missing or the positions were rewritten.
	BreakGap = "gap"
	// BreakPrev means an entry does not carry the hash of the entry before it.
	BreakPrev = "prev"
	// BreakHash means the hash of an entry is not the hash of its fields.
	BreakHash = "hash"
)

// LogEntry is one entry of the action log with its place in the chain of its tenant. The tenant id is
// not part of it, so the chain still verifies after a restore into another tenant (ADR-0126).
type LogEntry struct {
	Seq         int64
	ID          uuid.UUID
	At          time.Time
	Principal   uuid.UUID
	Responsible uuid.UUID
	Action      string
	Subject     string
	Prev        [sha256.Size]byte
	Hash        [sha256.Size]byte
}

// atText is the time of an entry as the chain hashes it and the export writes it: UTC, with the six
// digits of a PostgreSQL timestamp.
func atText(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000Z")
}

// Sum is the hash an entry must carry: SHA-256 of nine lines joined by LF, the format name, the hash of
// the entry before it as hex, the position, the id, the time, both principals, the action and the
// subject. The database computes the same text in identity.action_log_hash, and a test holds the two to
// one vector.
func (e LogEntry) Sum() [sha256.Size]byte {
	text := LogFormat + "\n" +
		hex.EncodeToString(e.Prev[:]) + "\n" +
		strconv.FormatInt(e.Seq, 10) + "\n" +
		e.ID.String() + "\n" +
		atText(e.At) + "\n" +
		e.Principal.String() + "\n" +
		e.Responsible.String() + "\n" +
		e.Action + "\n" +
		e.Subject
	return sha256.Sum256([]byte(text))
}

// logLine is one line of the JSONL export. It holds exactly the hashed fields, so a reader can check the
// hash of a line and the continuity between two lines without anything else.
type logLine struct {
	Format      string `json:"format"`
	Seq         int64  `json:"seq"`
	ID          string `json:"id"`
	At          string `json:"at"`
	Principal   string `json:"principal"`
	Responsible string `json:"responsible"`
	Action      string `json:"action"`
	Subject     string `json:"subject"`
	Prev        string `json:"prev"`
	Hash        string `json:"hash"`
}

// Line is the entry as one line of the export, ending in a newline. Markup is not escaped, because the
// reader is a SIEM and not a browser.
func (e LogEntry) Line() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(logLine{
		Format:      LogFormat,
		Seq:         e.Seq,
		ID:          e.ID.String(),
		At:          atText(e.At),
		Principal:   e.Principal.String(),
		Responsible: e.Responsible.String(),
		Action:      e.Action,
		Subject:     e.Subject,
		Prev:        hex.EncodeToString(e.Prev[:]),
		Hash:        hex.EncodeToString(e.Hash[:]),
	})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// LogBreak is the first place a chain does not hold.
type LogBreak struct {
	// Seq is the position of the first entry that fails, as that entry carries it.
	Seq int64 `json:"seq"`
	// Reason is BreakGap, BreakPrev or BreakHash.
	Reason string `json:"reason"`
}

// LogReport is what VerifyLog found. Entries is the number of entries read, the one that fails included.
// HeadSeq and Head are the position and hash of the last entry that held, which a reader keeps elsewhere
// to show later that nothing after it was rewritten and nothing before it was removed.
type LogReport struct {
	Tenant  uuid.UUID `json:"tenant"`
	Entries int64     `json:"entries"`
	HeadSeq int64     `json:"head_seq"`
	Head    string    `json:"head_hash,omitempty"`
	Intact  bool      `json:"intact"`
	Break   *LogBreak `json:"break,omitempty"`
}

// chain walks entries in order and says where the first one fails. The zero value is the start of a
// chain: position 0 and a hash of 32 zero bytes, which is what the first entry carries as its previous.
type chain struct {
	seq  int64
	hash [sha256.Size]byte
}

// next checks the entry after the last one that passed and returns the reason it fails, or "".
func (c *chain) next(e LogEntry) string {
	switch {
	case e.Seq != c.seq+1:
		return BreakGap
	case e.Prev != c.hash:
		return BreakPrev
	case e.Hash != e.Sum():
		return BreakHash
	}
	c.seq, c.hash = e.Seq, e.Hash
	return ""
}

// LogPage reads at most limit entries of the tenant's chain whose position is above after, oldest first.
// A position is assigned under a lock held until commit, so entries commit in the order of their
// positions and a reader that continues from the last position it saw never skips one. The tenant must
// be the authenticated one, because LogPage trusts it.
func LogPage(ctx context.Context, db *sql.DB, tenant uuid.UUID, after int64, limit int) ([]LogEntry, error) {
	if tenant == uuid.Nil || after < 0 || limit < 1 || limit > LogPageSize {
		return nil, fmt.Errorf("%w: a tenant, a position of 0 or more and a limit from 1 to %d are required", ErrInvalidQuery, LogPageSize)
	}
	var entries []LogEntry
	err := inTenant(ctx, db, tenant, true, func(tx *sql.Tx) error {
		var err error
		entries, err = readChain(ctx, tx, after, limit)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("read the action log: %w", err)
	}
	return entries, nil
}

// VerifyLog walks the whole chain of a tenant in one read-only snapshot and reports the first entry that
// does not hold. It proves that what is stored is a chain. It cannot show that entries after the head
// were removed or that the tail was rewritten as a whole, which only a copy of an older head can
// (ADR-0126). The tenant must be the one the caller means, because VerifyLog trusts it.
func VerifyLog(ctx context.Context, db *sql.DB, tenant uuid.UUID) (LogReport, error) {
	report := LogReport{Tenant: tenant, Intact: true}
	if tenant == uuid.Nil {
		return report, fmt.Errorf("%w: a tenant is required", ErrInvalidQuery)
	}
	err := inTenant(ctx, db, tenant, true, func(tx *sql.Tx) error {
		var c chain
		after := int64(0)
		for {
			page, err := readChain(ctx, tx, after, LogPageSize)
			if err != nil {
				return err
			}
			for _, e := range page {
				report.Entries++
				if reason := c.next(e); reason != "" {
					report.Intact = false
					report.Break = &LogBreak{Seq: e.Seq, Reason: reason}
					return nil
				}
				report.HeadSeq, report.Head = e.Seq, hex.EncodeToString(e.Hash[:])
			}
			if len(page) < LogPageSize {
				return nil
			}
			after = page[len(page)-1].Seq
		}
	})
	if err != nil {
		return report, fmt.Errorf("verify the action log: %w", err)
	}
	return report, nil
}

// readChain reads one page of the chain of the current tenant, in the order of its positions.
func readChain(ctx context.Context, tx *sql.Tx, after int64, limit int) ([]LogEntry, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT seq, id, lower(sys_period), principal_id, responsible_id, action, subject, prev_hash, hash
		FROM identity.action_log
		WHERE tenant_id = ipso.current_tenant() AND seq > $1
		ORDER BY seq
		LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var entries []LogEntry
	for rows.Next() {
		var e LogEntry
		var prev, sum []byte
		if err := rows.Scan(&e.Seq, &e.ID, &e.At, &e.Principal, &e.Responsible, &e.Action, &e.Subject, &prev, &sum); err != nil {
			return nil, err
		}
		if len(prev) != sha256.Size || len(sum) != sha256.Size {
			return nil, fmt.Errorf("entry %d holds a hash of the wrong length", e.Seq)
		}
		copy(e.Prev[:], prev)
		copy(e.Hash[:], sum)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
