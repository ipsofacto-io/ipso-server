package evals

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// EvalTenant is the tenant every eval call is made as. A gateway file may give it a route of its
// own, as the local one does, and a gateway file with no entry for it leaves it on the default routes.
var EvalTenant = uuid.MustParse("00000000-0000-4000-8000-000000000e09")

// RouteFiles are the files of one route: the gateway file, the recorded answers, the baseline, and
// the history of its scores. A cassette key does not name the model, so each route keeps its own
// (ADR-0165).
type RouteFiles struct {
	Name     string
	Gateway  string
	Cassette string
	Baseline string
	History  string
}

// Routes lists the routes in the order of the scores table. The local route is Qwen3-4B on the CI
// runner and keeps the files it had before there was a second route. The mistral route is the
// operator default of the gateway, the route tenants use.
var Routes = []RouteFiles{
	{
		Name:     "local",
		Gateway:  "testdata/local-model.json",
		Cassette: "testdata/cassette.json",
		Baseline: "testdata/baseline.json",
		History:  "testdata/history.jsonl",
	},
	{
		Name:     "mistral",
		Gateway:  "testdata/mistral/gateway.json",
		Cassette: "testdata/mistral/cassette.json",
		Baseline: "testdata/mistral/baseline.json",
		History:  "testdata/mistral/history.jsonl",
	},
}

// RouteRecord is what one route has recorded: the models its answers name and its baseline.
type RouteRecord struct {
	Name     string
	Models   []string
	Baseline Baseline
}

// LoadRoute reads what a route has recorded. A route with no files has no models and an empty baseline.
func LoadRoute(files RouteFiles) (RouteRecord, error) {
	cassette, err := LoadCassette(files.Cassette)
	if err != nil {
		return RouteRecord{}, err
	}
	baseline, err := LoadBaseline(files.Baseline)
	if err != nil {
		return RouteRecord{}, err
	}
	return RouteRecord{Name: files.Name, Models: cassette.Models(), Baseline: baseline}, nil
}

// InheritFloors returns next with the floor of each metric that has none, taken from the first of the
// other baselines that has one. A floor is a product target and not a property of a model, so every route
// holds the same one, and the first update of a route would otherwise record a baseline that no floor guards.
func InheritFloors(next Baseline, others ...Baseline) Baseline {
	out := make(Baseline, len(next))
	for name, entry := range next {
		if entry.Min == nil {
			for _, other := range others {
				if floor := other[name].Min; floor != nil {
					kept := *floor
					entry.Min = &kept
					break
				}
			}
		}
		out[name] = entry
	}
	return out
}

const notRecorded = "not recorded"

// ScoresTable renders one row per metric with its floor and the baseline score of each route, as a
// Markdown table. A route that has not recorded a metric says so.
func ScoresTable(routes []RouteRecord) string {
	names := map[string]bool{}
	for _, route := range routes {
		for name := range route.Baseline {
			names[name] = true
		}
	}
	var b strings.Builder
	b.WriteString("| Metric | Floor |")
	for _, route := range routes {
		fmt.Fprintf(&b, " %s |", routeHeading(route))
	}
	b.WriteString("\n| --- | --- |")
	for range routes {
		b.WriteString(" --- |")
	}
	b.WriteString("\n")
	for _, name := range sortedKeys(names) {
		floor := "none"
		for _, route := range routes {
			if min := route.Baseline[name].Min; min != nil {
				floor = formatScore(*min)
				break
			}
		}
		fmt.Fprintf(&b, "| `%s` | %s |", name, floor)
		for _, route := range routes {
			cell := notRecorded
			if entry, ok := route.Baseline[name]; ok {
				cell = formatScore(entry.Score)
			}
			fmt.Fprintf(&b, " %s |", cell)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func routeHeading(route RouteRecord) string {
	if len(route.Models) == 0 {
		return fmt.Sprintf("%s (%s)", route.Name, notRecorded)
	}
	return fmt.Sprintf("%s (%s)", route.Name, strings.Join(route.Models, ", "))
}

func formatScore(score float64) string {
	return strconv.FormatFloat(score, 'f', -1, 64)
}

const (
	scoresStart = "<!-- scores:start -->"
	scoresEnd   = "<!-- scores:end -->"
)

// ScoresBlock returns the text of doc between the scores markers, without the newlines around it.
func ScoresBlock(doc string) (string, error) {
	start := strings.Index(doc, scoresStart)
	end := strings.Index(doc, scoresEnd)
	if start < 0 || end < start {
		return "", fmt.Errorf("the document has no %s and %s pair", scoresStart, scoresEnd)
	}
	return strings.Trim(doc[start+len(scoresStart):end], "\n"), nil
}

// ReplaceScores returns doc with the text between the scores markers replaced by table.
func ReplaceScores(doc, table string) (string, error) {
	if _, err := ScoresBlock(doc); err != nil {
		return "", err
	}
	start := strings.Index(doc, scoresStart) + len(scoresStart)
	end := strings.Index(doc, scoresEnd)
	return doc[:start] + "\n" + strings.TrimRight(table, "\n") + "\n" + doc[end:], nil
}
