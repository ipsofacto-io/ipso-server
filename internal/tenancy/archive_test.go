package tenancy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/google/uuid"
)

func testIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testHeader(tables ...string) header {
	return header{
		Format:     Format,
		Tenant:     uuid.MustParse("00000000-0000-4000-8000-0000000000aa"),
		Name:       "synthetic",
		ExportedAt: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC),
		Schema:     "abc",
		Tables:     tables,
	}
}

// writeArchive writes tables with the real writer. rows maps a table to its JSON rows.
func writeArchive(t *testing.T, id *age.X25519Identity, h header, rows map[string][]string) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := newArchiveWriter(&out, []age.Recipient{id.Recipient()}, h)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range h.Tables {
		err := w.table(table, func(emit func([]byte) error) error {
			for _, row := range rows[table] {
				if err := emit([]byte(row)); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := w.finish(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// sealLines encrypts hand-made lines, so a test can break any rule the writer keeps.
func sealLines(t *testing.T, id *age.X25519Identity, lines ...string) []byte {
	t.Helper()
	var out bytes.Buffer
	enc, err := age.Encrypt(&out, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(enc)
	for _, l := range lines {
		_, _ = io.WriteString(zw, l+"\n")
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

type rowOut struct{ table, row string }

func readAll(t *testing.T, archive []byte, id *age.X25519Identity) ([]rowOut, error) {
	t.Helper()
	r, err := openArchive(bytes.NewReader(archive), []age.Identity{id})
	if err != nil {
		return nil, err
	}
	var got []rowOut
	for {
		table, row, err := r.next()
		if errors.Is(err, io.EOF) {
			return got, nil
		}
		if err != nil {
			return got, err
		}
		got = append(got, rowOut{table, string(row)})
	}
}

func headerLine(t *testing.T, h header) string {
	t.Helper()
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestArchiveRoundTripKeepsOrderAndEmptyTables(t *testing.T) {
	id := testIdentity(t)
	h := testHeader("a.one", "a.empty", "b.two")
	archive := writeArchive(t, id, h, map[string][]string{
		"a.one": {`{"id":1}`, `{"id":2,"s":"line\nbreak"}`},
		"b.two": {`{"id":3}`},
	})
	got, err := readAll(t, archive, id)
	if err != nil {
		t.Fatal(err)
	}
	want := []rowOut{{"a.one", `{"id":1}`}, {"a.one", `{"id":2,"s":"line\nbreak"}`}, {"b.two", `{"id":3}`}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row %d = %v, want %v", i, got[i], want[i])
		}
	}
	r, err := openArchive(bytes.NewReader(archive), []age.Identity{id})
	if err != nil || r.hdr.Name != "synthetic" || r.hdr.Tenant != h.Tenant {
		t.Fatalf("header = %+v, %v", r.hdr, err)
	}
}

func TestArchiveIsEncryptedToItsRecipientsOnly(t *testing.T) {
	id, other := testIdentity(t), testIdentity(t)
	archive := writeArchive(t, id, testHeader("a.one"), map[string][]string{"a.one": {`{"secret":"hunter2"}`}})
	if bytes.Contains(archive, []byte("hunter2")) || bytes.Contains(archive, []byte("synthetic")) {
		t.Fatal("the archive holds plaintext")
	}
	if _, err := readAll(t, archive, other); !errors.Is(err, ErrArchive) {
		t.Fatalf("another identity opened it: %v", err)
	}
}

func TestArchiveRefusesWhatTheTrailerDoesNotSay(t *testing.T) {
	id := testIdentity(t)
	h := testHeader("a.one", "b.two")
	hl := headerLine(t, h)
	emptySum := newSums().sum()
	one := newSums()
	one.add([]byte(`{"id":1}`))
	goodTrailer := func(a tableSum, b tableSum) string {
		files := emptySum
		line, _ := json.Marshal(wire{End: true, Tables: map[string]tableSum{"a.one": a, "b.two": b}, Files: &files})
		return string(line)
	}
	row := func(table, body string) string { return `{"table":"` + table + `","row":` + body + `}` }

	cases := map[string][]string{
		"row changed after the trailer was computed": {hl, row("a.one", `{"id":2}`), goodTrailer(one.sum(), emptySum)},
		"row missing":        {hl, goodTrailer(one.sum(), emptySum)},
		"no trailer":         {hl, row("a.one", `{"id":1}`)},
		"data after trailer": {hl, row("a.one", `{"id":1}`), goodTrailer(one.sum(), emptySum), row("a.one", `{"id":1}`)},
		"unknown table":      {hl, row("evil.table", `{"id":1}`), goodTrailer(one.sum(), emptySum)},
		"tables out of order": {hl, row("b.two", `{"id":1}`), row("a.one", `{"id":1}`),
			goodTrailer(one.sum(), one.sum())},
		"trailer lists too few tables": {hl, row("a.one", `{"id":1}`),
			`{"end":true,"tables":{"a.one":{"rows":1,"sha256":"` + one.sum().SHA256 + `"}}}`},
		"unknown field":           {hl, `{"table":"a.one","row":{"id":1},"extra":true}`, goodTrailer(one.sum(), emptySum)},
		"trailing data in a line": {hl, row("a.one", `{"id":1}`) + ` {}`, goodTrailer(one.sum(), emptySum)},
		"row line without row":    {hl, `{"table":"a.one"}`, goodTrailer(one.sum(), emptySum)},
		"trailer with a row":      {hl, `{"end":true,"table":"a.one","row":{}}`},
		"not json":                {hl, `not json`},
	}
	for name, lines := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := readAll(t, sealLines(t, id, lines...), id)
			if !errors.Is(err, ErrArchive) {
				t.Fatalf("got %v, want ErrArchive", err)
			}
		})
	}
	t.Run("the good one passes", func(t *testing.T) {
		if _, err := readAll(t, sealLines(t, id, hl, row("a.one", `{"id":1}`), goodTrailer(one.sum(), emptySum)), id); err != nil {
			t.Fatal(err)
		}
	})
}

func TestArchiveRefusesABadHeader(t *testing.T) {
	id := testIdentity(t)
	good := testHeader("a.one")
	bad := map[string]header{}
	h := good
	h.Format = "ipso-tenant-export/3"
	bad["other format"] = h
	h = good
	h.Tenant = uuid.Nil
	bad["no tenant"] = h
	h = good
	h.Schema = ""
	bad["no schema"] = h
	h = good
	h.Tables = nil
	bad["no tables"] = h
	h = good
	h.Tables = []string{"a.one", "a.one"}
	bad["duplicate table"] = h
	for name, hdr := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := readAll(t, sealLines(t, id, headerLine(t, hdr)), id)
			if !errors.Is(err, ErrArchive) {
				t.Fatalf("got %v, want ErrArchive", err)
			}
		})
	}
	t.Run("a stream that is not gzip", func(t *testing.T) {
		var out bytes.Buffer
		enc, _ := age.Encrypt(&out, id.Recipient())
		_, _ = io.WriteString(enc, "plain text")
		_ = enc.Close()
		if _, err := readAll(t, out.Bytes(), id); !errors.Is(err, ErrArchive) {
			t.Fatalf("got %v, want ErrArchive", err)
		}
	})
	t.Run("not age at all", func(t *testing.T) {
		if _, err := readAll(t, []byte("plain text, not an age file"), id); !errors.Is(err, ErrArchive) {
			t.Fatalf("got %v, want ErrArchive", err)
		}
	})
}

func TestArchiveRefusesALineOverTheCap(t *testing.T) {
	id := testIdentity(t)
	huge := `{"table":"a.one","row":{"s":"` + strings.Repeat("x", maxLine) + `"}}`
	_, err := readAll(t, sealLines(t, id, headerLine(t, testHeader("a.one")), huge), id)
	if !errors.Is(err, ErrArchive) || !strings.Contains(err.Error(), "longer") {
		t.Fatalf("got %v, want a line-length ErrArchive", err)
	}
}

func TestArchiveDetectsDamageAndTruncation(t *testing.T) {
	id := testIdentity(t)
	archive := writeArchive(t, id, testHeader("a.one"), map[string][]string{"a.one": {`{"id":1}`, `{"id":2}`}})
	for _, i := range []int{len(archive) / 2, len(archive) - 3} {
		flipped := bytes.Clone(archive)
		flipped[i] ^= 0x40
		if _, err := readAll(t, flipped, id); !errors.Is(err, ErrArchive) {
			t.Fatalf("byte %d changed: got %v, want ErrArchive", i, err)
		}
	}
	for _, n := range []int{len(archive) - 1, len(archive) - 40, len(archive) / 2} {
		if _, err := readAll(t, archive[:n], id); !errors.Is(err, ErrArchive) {
			t.Fatalf("cut to %d bytes: got %v, want ErrArchive", n, err)
		}
	}
}

func TestArchiveWriterKeepsItsRules(t *testing.T) {
	id := testIdentity(t)
	h := testHeader("a.one", "b.two")
	if _, err := newArchiveWriter(io.Discard, nil, h); err == nil {
		t.Fatal("a writer without recipients was made")
	}
	w, err := newArchiveWriter(io.Discard, []age.Recipient{id.Recipient()}, h)
	if err != nil {
		t.Fatal(err)
	}
	noRows := func(func([]byte) error) error { return nil }
	if err := w.table("b.two", noRows); err == nil {
		t.Fatal("a table out of order was written")
	}
	if err := w.table("a.one", noRows); err != nil {
		t.Fatal(err)
	}
	if err := w.finish(); err == nil {
		t.Fatal("finish succeeded with a table missing")
	}
}

func TestArchiveCarriesFilesAfterTheRowsAndTheReaderSkipsThem(t *testing.T) {
	id := testIdentity(t)
	h := testHeader("a.one")
	var out bytes.Buffer
	w, err := newArchiveWriter(&out, []age.Recipient{id.Recipient()}, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.file("edr/current/x.md", "text"); err == nil {
		t.Fatal("a file before the last table was written")
	}
	if err := w.table("a.one", func(emit func([]byte) error) error { return emit([]byte(`{"id":1}`)) }); err != nil {
		t.Fatal(err)
	}
	for _, f := range [][2]string{{"edr/current/a.md", "# A\n<b> & \"q\""}, {"edr/history/b.md", "# B"}} {
		if err := w.file(f[0], f[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.file("", "x"); err == nil {
		t.Fatal("an empty path was written")
	}
	if err := w.finish(); err != nil {
		t.Fatal(err)
	}
	got, err := readAll(t, out.Bytes(), id)
	if err != nil || len(got) != 1 || got[0].table != "a.one" {
		t.Fatalf("rows = %v, %v", got, err)
	}
}

func TestArchiveChecksFilesAgainstTheTrailer(t *testing.T) {
	id := testIdentity(t)
	hl := headerLine(t, testHeader("a.one"))
	row := `{"table":"a.one","row":{"id":1}}`
	fileA, fileB := `{"file":"edr/current/a.md","text":"A"}`, `{"file":"edr/current/b.md","text":"B"}`
	one := newSums()
	one.add([]byte(`{"id":1}`))
	both := newSums()
	both.add([]byte(fileA))
	both.add([]byte(fileB))
	trailer := func(files *tableSum) string {
		line, _ := json.Marshal(wire{End: true, Tables: map[string]tableSum{"a.one": one.sum()}, Files: files})
		return string(line)
	}
	sum := both.sum()
	empty := newSums().sum()
	good := []string{hl, row, fileA, fileB, trailer(&sum)}
	if _, err := readAll(t, sealLines(t, id, good...), id); err != nil {
		t.Fatalf("good: %v", err)
	}
	cases := map[string][]string{
		"a file changed":          {hl, row, fileA, `{"file":"edr/current/b.md","text":"C"}`, trailer(&sum)},
		"a file missing":          {hl, row, fileA, trailer(&sum)},
		"a file added":            {hl, row, fileA, fileB, `{"file":"edr/current/c.md","text":"C"}`, trailer(&sum)},
		"no files sum":            {hl, row, fileA, fileB, trailer(nil)},
		"files sum of none":       {hl, row, fileA, fileB, trailer(&empty)},
		"a row after a file":      {hl, row, fileA, row, trailer(&sum)},
		"a file with no text":     {hl, row, `{"file":"edr/current/a.md"}`, trailer(&sum)},
		"a file with a row":       {hl, row, `{"file":"edr/current/a.md","text":"A","table":"a.one","row":{}}`, trailer(&sum)},
		"a file with a files sum": {hl, row, `{"file":"edr/current/a.md","text":"A","files":{"rows":0,"sha256":"x"}}`, trailer(&sum)},
		"a trailer with a file":   {hl, row, fileA, fileB, `{"end":true,"file":"x","tables":{"a.one":{"rows":1,"sha256":"` + one.sum().SHA256 + `"}},"files":{"rows":2,"sha256":"` + sum.SHA256 + `"}}`},
	}
	for name, lines := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := readAll(t, sealLines(t, id, lines...), id); !errors.Is(err, ErrArchive) {
				t.Fatalf("got %v, want ErrArchive", err)
			}
		})
	}
}

func TestArchiveStillReadsFormatOne(t *testing.T) {
	id := testIdentity(t)
	h := testHeader("a.one")
	h.Format = formatV1
	one := newSums()
	one.add([]byte(`{"id":1}`))
	trailer := func(files *tableSum) string {
		line, _ := json.Marshal(wire{End: true, Tables: map[string]tableSum{"a.one": one.sum()}, Files: files})
		return string(line)
	}
	row := `{"table":"a.one","row":{"id":1}}`
	got, err := readAll(t, sealLines(t, id, headerLine(t, h), row, trailer(nil)), id)
	if err != nil || len(got) != 1 {
		t.Fatalf("format 1: %v, %v", got, err)
	}
	empty := newSums().sum()
	for name, lines := range map[string][]string{
		"a file in format 1":      {headerLine(t, h), row, `{"file":"edr/current/a.md","text":"A"}`, trailer(nil)},
		"a files sum in format 1": {headerLine(t, h), row, trailer(&empty)},
	} {
		if _, err := readAll(t, sealLines(t, id, lines...), id); !errors.Is(err, ErrArchive) {
			t.Errorf("%s: got %v, want ErrArchive", name, err)
		}
	}
}
