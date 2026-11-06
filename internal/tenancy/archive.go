package tenancy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"time"

	"filippo.io/age"
	"github.com/google/uuid"
)

// Format names the layout of an export. A change that an older restore cannot read gets a new number.
const Format = "ipso-tenant-export/1"

// maxLine bounds one line of an archive when it is read. A decision body or a rule is far smaller, and a
// larger line is refused instead of buffered.
const maxLine = 16 << 20

// ErrArchive is returned for an archive that is truncated, altered, or not an export of this schema. The
// text never quotes the archive.
var ErrArchive = errors.New("archive")

// An export is age over gzip over JSON lines. The first line is the header. Then come the rows of each
// table, in the order of the header, one line each: {"table":"identity.principal","row":{...}} with the
// row as to_jsonb printed it. The last line is the trailer, with the row count and SHA-256 of every
// table. The customer opens it with stock age, gunzip and jq.

type header struct {
	Format     string    `json:"format"`
	Tenant     uuid.UUID `json:"tenant"`
	Name       string    `json:"name"`
	ExportedAt time.Time `json:"exported_at"`
	Schema     string    `json:"schema"`
	Tables     []string  `json:"tables"`
}

type tableSum struct {
	Rows   int64  `json:"rows"`
	SHA256 string `json:"sha256"`
}

// wire is one data line or the trailer.
type wire struct {
	Table  string              `json:"table,omitempty"`
	Row    json.RawMessage     `json:"row,omitempty"`
	End    bool                `json:"end,omitempty"`
	Tables map[string]tableSum `json:"tables,omitempty"`
}

// sums tracks the row count and the hash of the table being written or read.
type sums struct {
	rows int64
	hash hash.Hash
}

func newSums() *sums { return &sums{hash: sha256.New()} }

func (s *sums) add(row []byte) {
	s.rows++
	s.hash.Write(row)
	s.hash.Write([]byte{'\n'})
}

func (s *sums) sum() tableSum {
	return tableSum{Rows: s.rows, SHA256: hex.EncodeToString(s.hash.Sum(nil))}
}

// archiveWriter writes an export. Tables are written in the order of the header, and an empty table is
// still written, so the trailer lists all of them.
type archiveWriter struct {
	enc    io.WriteCloser
	zw     *gzip.Writer
	bw     *bufio.Writer
	tables []string
	next   int
	done   map[string]tableSum
}

func newArchiveWriter(out io.Writer, recipients []age.Recipient, h header) (*archiveWriter, error) {
	if len(recipients) == 0 {
		return nil, errors.New("an export needs at least one recipient")
	}
	enc, err := age.Encrypt(out, recipients...)
	if err != nil {
		return nil, fmt.Errorf("start the encrypted export: %w", err)
	}
	zw := gzip.NewWriter(enc)
	w := &archiveWriter{enc: enc, zw: zw, bw: bufio.NewWriterSize(zw, 1<<20), tables: h.Tables, done: make(map[string]tableSum)}
	line, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("write the header: %w", err)
	}
	if err := w.writeLine(line); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *archiveWriter) writeLine(line []byte) error {
	if _, err := w.bw.Write(line); err != nil {
		return fmt.Errorf("write the export: %w", err)
	}
	if err := w.bw.WriteByte('\n'); err != nil {
		return fmt.Errorf("write the export: %w", err)
	}
	return nil
}

// table writes the next table of the header. fill calls emit once for each row, with the row as JSON.
func (w *archiveWriter) table(name string, fill func(emit func(row []byte) error) error) error {
	if w.next >= len(w.tables) || w.tables[w.next] != name {
		return errors.New("write the export: tables out of order")
	}
	w.next++
	quoted, err := json.Marshal(name)
	if err != nil {
		return fmt.Errorf("write the export: %w", err)
	}
	s := newSums()
	prefix := append([]byte(`{"table":`), quoted...)
	prefix = append(prefix, `,"row":`...)
	err = fill(func(row []byte) error {
		s.add(row)
		for _, part := range [][]byte{prefix, row, []byte("}\n")} {
			if _, err := w.bw.Write(part); err != nil {
				return fmt.Errorf("write the export: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	w.done[name] = s.sum()
	return nil
}

// finish writes the trailer and closes every layer. The export is complete only after it returns nil.
func (w *archiveWriter) finish() error {
	if w.next != len(w.tables) {
		return errors.New("write the export: tables are missing")
	}
	line, err := json.Marshal(wire{End: true, Tables: w.done})
	if err != nil {
		return fmt.Errorf("write the trailer: %w", err)
	}
	if err := w.writeLine(line); err != nil {
		return err
	}
	if err := w.bw.Flush(); err != nil {
		return fmt.Errorf("write the export: %w", err)
	}
	if err := w.zw.Close(); err != nil {
		return fmt.Errorf("write the export: %w", err)
	}
	if err := w.enc.Close(); err != nil {
		return fmt.Errorf("write the export: %w", err)
	}
	return nil
}

// archiveReader reads an export and checks it against its trailer.
type archiveReader struct {
	sc    *bufio.Scanner
	hdr   header
	pos   int
	cur   *sums
	done  map[string]tableSum
	ended bool
}

// openArchive decrypts the stream, reads the header, and returns a reader positioned at the first row. It
// checks the layout of the header and nothing about the database: the caller compares tables and shape.
func openArchive(in io.Reader, identities []age.Identity) (*archiveReader, error) {
	if len(identities) == 0 {
		return nil, errors.New("open the archive: no identity")
	}
	dec, err := age.Decrypt(in, identities...)
	if err != nil {
		return nil, fmt.Errorf("%w: it does not open with this identity: %w", ErrArchive, err)
	}
	zr, err := gzip.NewReader(dec)
	if err != nil {
		return nil, fmt.Errorf("%w: it is not compressed", ErrArchive)
	}
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	r := &archiveReader{sc: sc, pos: -1, done: make(map[string]tableSum)}
	line, err := r.line()
	if err != nil {
		return nil, err
	}
	if err := decodeStrict(line, &r.hdr); err != nil {
		return nil, fmt.Errorf("%w: the header is unreadable", ErrArchive)
	}
	switch {
	case r.hdr.Format != Format:
		return nil, fmt.Errorf("%w: the format is not %s", ErrArchive, Format)
	case r.hdr.Tenant == uuid.Nil, r.hdr.Schema == "", len(r.hdr.Tables) == 0:
		return nil, fmt.Errorf("%w: the header is incomplete", ErrArchive)
	}
	seen := make(map[string]bool, len(r.hdr.Tables))
	for _, t := range r.hdr.Tables {
		if seen[t] {
			return nil, fmt.Errorf("%w: the header lists a table twice", ErrArchive)
		}
		seen[t] = true
	}
	return r, nil
}

func (r *archiveReader) line() ([]byte, error) {
	if !r.sc.Scan() {
		if err := r.sc.Err(); err != nil {
			if errors.Is(err, bufio.ErrTooLong) {
				return nil, fmt.Errorf("%w: a line is longer than %d bytes", ErrArchive, maxLine)
			}
			return nil, fmt.Errorf("%w: it is damaged or truncated", ErrArchive)
		}
		return nil, fmt.Errorf("%w: it ends before its trailer", ErrArchive)
	}
	return r.sc.Bytes(), nil
}

func decodeStrict(line []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

// closeTable stores the sums of the table being read.
func (r *archiveReader) closeTable() {
	if r.cur != nil {
		r.done[r.hdr.Tables[r.pos]] = r.cur.sum()
		r.cur = nil
	}
}

// next returns the next row and its table. At the end it checks the trailer against what was read and
// returns io.EOF only when they agree. The row is valid until the next call.
func (r *archiveReader) next() (string, []byte, error) {
	if r.ended {
		return "", nil, io.EOF
	}
	raw, err := r.line()
	if err != nil {
		return "", nil, err
	}
	var w wire
	if err := decodeStrict(raw, &w); err != nil {
		return "", nil, fmt.Errorf("%w: a line is unreadable", ErrArchive)
	}
	if w.End {
		return "", nil, r.finish(w)
	}
	if w.Table == "" || len(w.Row) == 0 || w.Tables != nil {
		return "", nil, fmt.Errorf("%w: a line is not a row", ErrArchive)
	}
	idx := slices.Index(r.hdr.Tables, w.Table)
	switch {
	case idx < 0:
		return "", nil, fmt.Errorf("%w: a row names a table the header does not list", ErrArchive)
	case idx < r.pos:
		return "", nil, fmt.Errorf("%w: rows are out of order", ErrArchive)
	case idx > r.pos:
		r.closeTable()
		r.pos = idx
		r.cur = newSums()
	}
	r.cur.add(w.Row)
	return w.Table, w.Row, nil
}

// finish checks the trailer: every table of the header, with the count and hash that were read, and
// nothing after it.
func (r *archiveReader) finish(w wire) error {
	if w.Table != "" || len(w.Row) != 0 {
		return fmt.Errorf("%w: the trailer is malformed", ErrArchive)
	}
	r.closeTable()
	empty := newSums().sum()
	for _, name := range r.hdr.Tables {
		if _, ok := r.done[name]; !ok {
			r.done[name] = empty
		}
	}
	if len(w.Tables) != len(r.done) {
		return fmt.Errorf("%w: the trailer does not list the tables of the header", ErrArchive)
	}
	for name, got := range r.done {
		if want, ok := w.Tables[name]; !ok || want != got {
			return fmt.Errorf("%w: the rows do not match the trailer", ErrArchive)
		}
	}
	if r.sc.Scan() {
		return fmt.Errorf("%w: data follows the trailer", ErrArchive)
	}
	if err := r.sc.Err(); err != nil {
		return fmt.Errorf("%w: it is damaged or truncated", ErrArchive)
	}
	r.ended = true
	return io.EOF
}
