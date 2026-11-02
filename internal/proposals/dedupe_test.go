package proposals

import "testing"

func TestDedupeDropsRestatedAndKnownDecisions(t *testing.T) {
	found := []Proposal{
		{ExternalID: "issuecomment-1", Title: "Expose Prometheus metrics", Statement: "Every service exposes Prometheus metrics on port 9090."},
		{ExternalID: "issuecomment-2", Title: "Prometheus metrics on 9090", Statement: "All services expose Prometheus metrics on 9090."},
		{ExternalID: "issuecomment-3", Title: "Use Postgres for money", Statement: "Services that store money use Postgres."},
		{ExternalID: "issuecomment-4", Title: "Back up Postgres daily", Statement: "Every Postgres database has a daily backup."},
	}
	kept, dropped := Dedupe(found, []string{"Use Postgres for services that store money", ""})
	if dropped != 2 || len(kept) != 2 || kept[0].ExternalID != "issuecomment-1" || kept[1].ExternalID != "issuecomment-4" {
		t.Fatalf("kept %+v dropped %d", kept, dropped)
	}
}

func TestClassifierReadsDecisionPhrasings(t *testing.T) {
	for _, text := range []string{
		"From now on all new infrastructure is written in OpenTofu.",
		"We're going with PostgreSQL full-text search for now.",
		"We are moving all frontend builds to Vite.",
		"The decision is that every payment endpoint requires an idempotency key.",
		"Release branches are gone: we ship from main, as decided at the retro.",
		"Every error response follows RFC 9457 from this release on.",
		"Two outcomes from the design review: we use gRPC internally.",
		"The v1 API is deprecated as of this release.",
		"Settled: the warehouse is BigQuery in the EU region.",
		"We standardised on Renovate for dependency updates.",
		"Abbiamo deciso di usare Redis per la cache.",
		"Wir haben entschieden, Kafka durch NATS zu ersetzen.",
		"Nous avons décidé d'utiliser Tailwind.",
		"Hemos decidido usar Flutter.",
	} {
		if !decisionLike.MatchString(text) {
			t.Errorf("not read as a decision: %q", text)
		}
	}
	for _, text := range []string{
		"Should we decide on a single region for staging?",
		"I decided to split this PR in two.",
		"Maybe we go with DuckDB for the local scripts? Not sure yet.",
		"Can we write an ADR for this before merging?",
	} {
		if decisionLike.MatchString(text) {
			t.Errorf("read as a decision: %q", text)
		}
	}
}
