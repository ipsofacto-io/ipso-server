package evals

import (
	"os"
	"strings"
	"testing"
)

// scoresDoc is the page that holds the scores of every route side by side.
const scoresDoc = "../../docs/evals.md"

func loadRoutes(t *testing.T) []RouteRecord {
	t.Helper()
	records := make([]RouteRecord, 0, len(Routes))
	for _, files := range Routes {
		record, err := LoadRoute(files)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return records
}

// writeScoresDoc rewrites the table of docs/evals.md from the committed baselines and cassettes.
func writeScoresDoc() error {
	records := make([]RouteRecord, 0, len(Routes))
	for _, files := range Routes {
		record, err := LoadRoute(files)
		if err != nil {
			return err
		}
		records = append(records, record)
	}
	raw, err := os.ReadFile(scoresDoc)
	if err != nil {
		return err
	}
	next, err := ReplaceScores(string(raw), ScoresTable(records))
	if err != nil {
		return err
	}
	return os.WriteFile(scoresDoc, []byte(next), 0o644)
}

func routeOf(t *testing.T, name string) RouteFiles {
	t.Helper()
	var known []string
	for _, files := range Routes {
		if files.Name == name {
			return files
		}
		known = append(known, files.Name)
	}
	t.Fatalf("-route %q is not one of %s", name, strings.Join(known, ", "))
	return RouteFiles{}
}

// docs/evals.md shows the baseline of each route, so it cannot drift from the files that gate.
// A stale table is rewritten by `go test ./internal/evals -run '^TestEvals$' -route <route> -update`.
func TestScoresTable(t *testing.T) {
	raw, err := os.ReadFile(scoresDoc)
	if err != nil {
		t.Fatal(err)
	}
	have, err := ScoresBlock(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimRight(ScoresTable(loadRoutes(t)), "\n")
	if have != want {
		t.Fatalf("docs/evals.md is out of date with the baselines. Its table should read:\n%s", want)
	}
}

func TestScoresTableSaysWhatIsNotRecorded(t *testing.T) {
	floor := 0.9
	table := ScoresTable([]RouteRecord{
		{Name: "local", Models: []string{"qwen3-4b-q4_k_m"}, Baseline: Baseline{"a": {Score: 0.95, Min: &floor}, "b": {Score: 0.5}}},
		{Name: "eu", Baseline: Baseline{"a": {Score: 0.93}}},
	})
	for _, want := range []string{
		"| Metric | Floor | local (qwen3-4b-q4_k_m) | eu (not recorded) |",
		"| `a` | 0.9 | 0.95 | 0.93 |",
		"| `b` | none | 0.5 | not recorded |",
	} {
		if !strings.Contains(table, want) {
			t.Errorf("table lacks %q:\n%s", want, table)
		}
	}
}

func TestReplaceScoresKeepsTheTextAround(t *testing.T) {
	doc := "before\n\n" + scoresStart + "\nold\n" + scoresEnd + "\n\nafter\n"
	got, err := ReplaceScores(doc, "new row\n")
	if err != nil {
		t.Fatal(err)
	}
	if want := "before\n\n" + scoresStart + "\nnew row\n" + scoresEnd + "\n\nafter\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if _, err := ReplaceScores("no markers", "x"); err == nil {
		t.Fatal("a document with no markers was accepted")
	}
}

// A floor is a product target (section 9.9), not a property of a model, so both routes hold the same one.
func TestRoutesShareTheirFloors(t *testing.T) {
	records := loadRoutes(t)
	floors := map[string]float64{}
	for _, record := range records {
		for name, entry := range record.Baseline {
			if entry.Min == nil {
				continue
			}
			if first, ok := floors[name]; ok && first != *entry.Min {
				t.Errorf("%s has the floor %v on one route and %v on route %s", name, first, *entry.Min, record.Name)
			}
			floors[name] = *entry.Min
		}
	}
}

// Every route's gateway file parses, and the gateway starts on it. The gateway refuses an operator
// route outside the EU, so a gateway file of the mistral route that starts is an EU route.
func TestRouteGatewaysStart(t *testing.T) {
	t.Setenv("IPSO_LLM_MISTRAL", "key-for-the-test")
	t.Setenv("IPSO_LLM_LOCAL", "key-for-the-test")
	for _, files := range Routes {
		t.Run(files.Name, func(t *testing.T) {
			if gateway := newGateway(t, files); gateway == nil {
				t.Fatal("no gateway")
			}
		})
	}
}
