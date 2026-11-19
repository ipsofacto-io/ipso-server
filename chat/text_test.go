package chat

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestWaiverDigestNamesTheDecisionAndTheTicketOnly(t *testing.T) {
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	text, ids := WaiverDigest([]WaiverNotice{
		{ID: uuid.MustParse("00000000-0000-4000-8000-0000000000a1"), Decision: decision, Days: 14, Ticket: "OPS-1"},
		{ID: uuid.MustParse("00000000-0000-4000-8000-0000000000a2"), Decision: decision, Days: 9, Ticket: "OPS-2"},
		{ID: uuid.MustParse("00000000-0000-4000-8000-0000000000a3"), Decision: decision, Days: 0, Ticket: "OPS-3"},
	})
	if !strings.Contains(text, "expires in 14 days") || !strings.Contains(text, "expires today") || !strings.Contains(text, "OPS-1") || !strings.Contains(text, decision.String()) {
		t.Fatalf("text = %q", text)
	}
	if strings.Contains(text, "OPS-2") || strings.Contains(text, "Ada") || strings.Contains(text, "http") {
		t.Fatalf("text = %q", text)
	}
	if len(ids) != 2 {
		t.Fatalf("ids = %v", ids)
	}
}

func TestPremiseDigestNamesThePremiseOnly(t *testing.T) {
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	text, ids := PremiseDigest([]PremiseNotice{
		{ID: uuid.MustParse("00000000-0000-4000-8000-0000000000b1"), Decision: decision, Premise: "tls-version"},
		{ID: uuid.MustParse("00000000-0000-4000-8000-0000000000b2"), Decision: decision, Premise: "has a space"},
	})
	if text != "Premise failures\ndecision "+decision.String()+" premise tls-version\n" {
		t.Fatalf("text = %q", text)
	}
	if len(ids) != 1 {
		t.Fatalf("ids = %v", ids)
	}
}

func TestDigestsStopAtTwentyLines(t *testing.T) {
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	lines := make([]PremiseNotice, 25)
	for i := range lines {
		lines[i] = PremiseNotice{ID: uuid.New(), Decision: decision, Premise: "tls-version"}
	}
	_, ids := PremiseDigest(lines)
	if len(ids) != LineLimit {
		t.Fatalf("ids = %d, want %d", len(ids), LineLimit)
	}
}
