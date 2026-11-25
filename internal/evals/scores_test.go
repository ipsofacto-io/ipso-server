package evals

import (
	"fmt"
	"os"
	"slices"
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

// floorMismatches names each metric whose floor on one route is missing or different from the floor it
// has on another route, for the metrics each route has recorded.
func floorMismatches(records []RouteRecord) []string {
	floors := map[string]float64{}
	for _, record := range records {
		for name, entry := range record.Baseline {
			if entry.Min != nil {
				floors[name] = *entry.Min
			}
		}
	}
	var out []string
	for _, record := range records {
		for name, entry := range record.Baseline {
			want, ok := floors[name]
			switch {
			case !ok:
			case entry.Min == nil:
				out = append(out, fmt.Sprintf("%s has no floor on route %s, and %v elsewhere", name, record.Name, want))
			case *entry.Min != want:
				out = append(out, fmt.Sprintf("%s has the floor %v on route %s, and %v elsewhere", name, *entry.Min, record.Name, want))
			}
		}
	}
	slices.Sort(out)
	return out
}

// A floor is a product target (section 9.9), not a property of a model, so every route that has recorded a
// metric holds the same floor for it.
func TestRoutesShareTheirFloors(t *testing.T) {
	if got := floorMismatches(loadRoutes(t)); len(got) != 0 {
		t.Fatalf("the routes disagree on a floor: %v", got)
	}
}

func TestFloorMismatchesNamesAMissingAndADifferentFloor(t *testing.T) {
	high, low := 0.9, 0.8
	records := []RouteRecord{
		{Name: "local", Baseline: Baseline{"a": {Score: 0.95, Min: &high}, "b": {Score: 0.9, Min: &low}, "c": {Score: 0.5}}},
		{Name: "eu", Baseline: Baseline{"a": {Score: 0.93}, "b": {Score: 0.85, Min: &high}, "c": {Score: 0.4}, "d": {Score: 1}}},
	}
	got := floorMismatches(records)
	want := []string{"a has no floor on route eu, and 0.9 elsewhere"}
	// b is the one floor that two routes hold differently: the message names whichever route is read last.
	if len(got) != 2 || got[0] != want[0] || !strings.HasPrefix(got[1], "b has the floor ") {
		t.Fatalf("mismatches = %v", got)
	}
	if got := floorMismatches([]RouteRecord{{Name: "local", Baseline: Baseline{"a": {Score: 1, Min: &high}}}, {Name: "eu"}}); len(got) != 0 {
		t.Fatalf("a route that has not recorded a metric has a floor mismatch: %v", got)
	}
}

// The first update of a route starts from an empty baseline, so it takes its floors from the routes that have
// them. Without that, a production baseline recorded below a product target would pass its gate for good.
func TestInheritFloorsGivesAFirstBaselineTheFloorsOfTheOtherRoutes(t *testing.T) {
	high, low := 0.9, 0.8
	local := Baseline{"a": {Score: 0.95, Min: &high}, "b": {Score: 0.9}, "c": {Score: 0.7, Min: &low}}
	scores := Scores{"a": 0.5, "b": 0.6, "c": 0.7, "d": 0.4}
	first := InheritFloors(Update(Baseline{}, scores), local)
	if first["a"].Min == nil || *first["a"].Min != 0.9 || first["c"].Min == nil || *first["c"].Min != 0.8 || first["b"].Min != nil || first["d"].Min != nil {
		t.Fatalf("first baseline = %+v", first)
	}
	// A below-floor first recording fails its own gate, so it is not accepted by the next gate run.
	if got := Gate(first, Metrics{"a": Count(5, 10), "b": Count(6, 10), "c": Count(7, 10), "d": Count(4, 10)}); len(got) != 2 {
		t.Fatalf("a first baseline below its floors passes the gate: %v", got)
	}
	// The floor of the route itself wins, and the copy is not shared with the other baseline.
	own := 0.7
	kept := InheritFloors(Baseline{"a": {Score: 0.8, Min: &own}, "c": {Score: 0.7}}, local)
	if *kept["a"].Min != 0.7 {
		t.Fatalf("an own floor was replaced: %+v", kept["a"])
	}
	*kept["c"].Min = 0.1
	if *local["c"].Min != 0.8 {
		t.Fatal("the inherited floor aliases the other baseline")
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
