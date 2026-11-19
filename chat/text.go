package chat

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// WaiverNotice is one undelivered waiver notice. The text names the decision, the offset, and the
// ticket. It does not name a person, a reason, or a URL.
type WaiverNotice struct {
	ID       uuid.UUID
	Decision uuid.UUID
	Days     int
	Ticket   string
}

// PremiseNotice is one open premise reason. The text names the decision and the premise id.
type PremiseNotice struct {
	ID       uuid.UUID
	Decision uuid.UUID
	Premise  string
}

// WaiverDigest formats at most LineLimit notices. The ids are the ones the text includes.
func WaiverDigest(lines []WaiverNotice) (string, []uuid.UUID) {
	var b strings.Builder
	var ids []uuid.UUID
	for _, line := range lines {
		if len(ids) == LineLimit {
			break
		}
		phrase, ok := expiryPhrase(line.Days)
		if !ok || line.ID == uuid.Nil || line.Decision == uuid.Nil || !plainText(line.Ticket, 200) {
			continue
		}
		if len(ids) == 0 {
			b.WriteString("Waiver notices\n")
		}
		fmt.Fprintf(&b, "decision %s %s, ticket %s\n", line.Decision, phrase, line.Ticket)
		ids = append(ids, line.ID)
	}
	return b.String(), ids
}

// PremiseDigest formats at most LineLimit open reasons. The ids are the ones the text includes.
func PremiseDigest(lines []PremiseNotice) (string, []uuid.UUID) {
	var b strings.Builder
	var ids []uuid.UUID
	for _, line := range lines {
		if len(ids) == LineLimit {
			break
		}
		if line.ID == uuid.Nil || line.Decision == uuid.Nil || !plainText(line.Premise, 128) || strings.Contains(line.Premise, " ") {
			continue
		}
		if len(ids) == 0 {
			b.WriteString("Premise failures\n")
		}
		fmt.Fprintf(&b, "decision %s premise %s\n", line.Decision, line.Premise)
		ids = append(ids, line.ID)
	}
	return b.String(), ids
}

func expiryPhrase(days int) (string, bool) {
	switch days {
	case 14:
		return "expires in 14 days", true
	case 3:
		return "expires in 3 days", true
	case 0:
		return "expires today", true
	default:
		return "", false
	}
}
