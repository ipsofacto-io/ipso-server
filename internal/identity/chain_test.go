package identity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The vector of ADR-0126, computed with Python's hashlib from the nine lines and not with this package,
// and the same one the integration test gives to identity.action_log_hash in SQL, so the two
// implementations of the hashed form are held to one answer.
var (
	vectorOne = LogEntry{
		Seq:         1,
		ID:          uuid.MustParse("018f3e6a-1c2b-7d4e-8f50-123456789abc"),
		At:          time.Date(2026, time.November, 15, 8, 30, 0, 123456000, time.UTC),
		Principal:   uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		Responsible: uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		Action:      "api.record_waiver",
		Subject:     `waiver w1 of "use-tls" \ é 日本`,
	}
	vectorOneHash = "3d0a1548f7077ac48f360148a5ce92e0dc57c63d8ac070b494079962b74ee2d2"

	vectorTwo = LogEntry{
		Seq:         2,
		ID:          uuid.MustParse("018f3e6a-1c2c-7000-8000-00000000000a"),
		At:          time.Date(2026, time.November, 15, 8, 30, 1, 0, time.UTC),
		Principal:   uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		Responsible: uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		Action:      "api.start_export",
		Subject:     "export 5",
	}
	vectorTwoHash = "e89b4fde2c6f69c80840a1bb0ffab16d8746e5760510782d21ec32c41b7f2f11"
)

func sealed(t *testing.T, e LogEntry, prev [32]byte) LogEntry {
	t.Helper()
	e.Prev = prev
	e.Hash = e.Sum()
	return e
}

func TestTheHashOfAnEntryIsTheVector(t *testing.T) {
	one := sealed(t, vectorOne, [32]byte{})
	if got := hex.EncodeToString(one.Hash[:]); got != vectorOneHash {
		t.Fatalf("hash %s, want %s", got, vectorOneHash)
	}
	two := sealed(t, vectorTwo, one.Hash)
	if got := hex.EncodeToString(two.Hash[:]); got != vectorTwoHash {
		t.Fatalf("hash %s, want %s", got, vectorTwoHash)
	}
}

func TestTheTimeIsHashedInUTCWithSixDigits(t *testing.T) {
	zone := time.FixedZone("CEST", 2*3600)
	local := vectorOne
	local.At = vectorOne.At.In(zone)
	if local.Sum() != vectorOne.Sum() {
		t.Fatal("the hash depends on the zone the time is held in")
	}
	if got := atText(time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)); got != "2026-01-02T03:04:05.000000Z" {
		t.Fatalf("a whole second is %s", got)
	}
}

func TestEveryFieldOfAnEntryIsHashed(t *testing.T) {
	base := vectorOne.Sum()
	other := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	for name, mutate := range map[string]func(*LogEntry){
		"prev":        func(e *LogEntry) { e.Prev[0] = 1 },
		"seq":         func(e *LogEntry) { e.Seq++ },
		"id":          func(e *LogEntry) { e.ID = other },
		"at":          func(e *LogEntry) { e.At = e.At.Add(time.Microsecond) },
		"principal":   func(e *LogEntry) { e.Principal = other },
		"responsible": func(e *LogEntry) { e.Responsible = other },
		"action":      func(e *LogEntry) { e.Action += "x" },
		"subject":     func(e *LogEntry) { e.Subject += " " },
	} {
		e := vectorOne
		mutate(&e)
		if e.Sum() == base {
			t.Errorf("the hash ignores %s", name)
		}
	}
}

// A line holds exactly what the hash covers, so a reader can hash it again.
func TestALineHoldsTheHashedFieldsAndRoundTrips(t *testing.T) {
	e := sealed(t, vectorOne, [32]byte{})
	line, err := e.Line()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(line, []byte("\n")) || bytes.Count(line, []byte("\n")) != 1 {
		t.Fatalf("a line is one object and a newline: %q", line)
	}
	var got map[string]any
	if err := json.Unmarshal(line, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"format": LogFormat, "seq": float64(1), "id": e.ID.String(), "at": "2026-11-15T08:30:00.123456Z",
		"principal": e.Principal.String(), "responsible": e.Responsible.String(), "action": e.Action,
		"subject": e.Subject, "prev": strings.Repeat("0", 64), "hash": vectorOneHash,
	}
	if len(got) != len(want) {
		t.Fatalf("%d keys, want %d: %v", len(got), len(want), got)
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %v, want %v", key, got[key], value)
		}
	}
	// The line gives the reader every field of the hashed text.
	prev, _ := hex.DecodeString(got["prev"].(string))
	back := LogEntry{
		Seq: int64(got["seq"].(float64)), ID: uuid.MustParse(got["id"].(string)), Action: got["action"].(string),
		Principal: uuid.MustParse(got["principal"].(string)), Responsible: uuid.MustParse(got["responsible"].(string)),
		Subject: got["subject"].(string),
	}
	back.At, err = time.Parse("2006-01-02T15:04:05.000000Z", got["at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	copy(back.Prev[:], prev)
	if hex.EncodeToString(func() []byte { s := back.Sum(); return s[:] }()) != got["hash"] {
		t.Fatal("a reader cannot recompute the hash from the line")
	}
}

func TestALineDoesNotEscapeMarkup(t *testing.T) {
	e := vectorOne
	e.Subject = "a <b> & c"
	line, err := e.Line()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(line, []byte(`"a <b> & c"`)) {
		t.Fatalf("markup was escaped: %s", line)
	}
}

func buildChain(t *testing.T) []LogEntry {
	t.Helper()
	one := sealed(t, vectorOne, [32]byte{})
	two := sealed(t, vectorTwo, one.Hash)
	three := vectorTwo
	three.Seq = 3
	three.ID = uuid.MustParse("018f3e6a-1c2d-7000-8000-00000000000b")
	three = sealed(t, three, two.Hash)
	return []LogEntry{one, two, three}
}

func check(entries []LogEntry) (*LogBreak, int64) {
	var c chain
	for _, e := range entries {
		if reason := c.next(e); reason != "" {
			return &LogBreak{Seq: e.Seq, Reason: reason}, c.seq
		}
	}
	return nil, c.seq
}

func TestAChainThatHoldsPasses(t *testing.T) {
	if broken, head := check(buildChain(t)); broken != nil || head != 3 {
		t.Fatalf("broken %+v, head %d", broken, head)
	}
	if broken, head := check(nil); broken != nil || head != 0 {
		t.Fatalf("an empty chain: %+v, %d", broken, head)
	}
}

// The tampering the check names: an edited entry, a removed one, a rewritten link, and a chain that does
// not start at 1.
func TestAChainThatDoesNotHoldIsRefusedAtTheFirstBadEntry(t *testing.T) {
	cases := map[string]struct {
		mutate func([]LogEntry) []LogEntry
		want   LogBreak
	}{
		"an edited subject": {func(c []LogEntry) []LogEntry { c[1].Subject = "export 6"; return c }, LogBreak{2, BreakHash}},
		"an edited action":  {func(c []LogEntry) []LogEntry { c[0].Action = "api.start_export"; return c }, LogBreak{1, BreakHash}},
		"a rewritten hash":  {func(c []LogEntry) []LogEntry { c[1].Hash[5] ^= 0xff; return c }, LogBreak{2, BreakHash}},
		"an entry rewritten with its own hash": {func(c []LogEntry) []LogEntry {
			c[1].Subject = "export 6"
			c[1].Hash = c[1].Sum()
			return c
		}, LogBreak{3, BreakPrev}},
		"a removed middle entry": {func(c []LogEntry) []LogEntry { return []LogEntry{c[0], c[2]} }, LogBreak{3, BreakGap}},
		"a removed first entry":  {func(c []LogEntry) []LogEntry { return c[1:] }, LogBreak{2, BreakGap}},
		"swapped positions":      {func(c []LogEntry) []LogEntry { return []LogEntry{c[0], c[2], c[1]} }, LogBreak{3, BreakGap}},
		"a repeated entry":       {func(c []LogEntry) []LogEntry { return []LogEntry{c[0], c[1], c[1]} }, LogBreak{2, BreakGap}},
		"a wrong previous hash":  {func(c []LogEntry) []LogEntry { c[2].Prev[0] ^= 1; return c }, LogBreak{3, BreakPrev}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			broken, _ := check(tc.mutate(buildChain(t)))
			if broken == nil || *broken != tc.want {
				t.Fatalf("got %+v, want %+v", broken, tc.want)
			}
		})
	}
}
