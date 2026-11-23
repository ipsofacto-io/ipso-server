package telemetrystack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/telemetry"
)

// The histograms the code records, as Prometheus names them when it takes them over OTLP: the unit is a suffix
// of the name, and a histogram is three series.
var emitted = map[string]bool{}

func init() {
	for _, base := range []string{"http_server_request_duration_seconds", "ipso_job_duration_seconds", "mcp_server_operation_duration_seconds"} {
		for _, suffix := range []string{"_bucket", "_count", "_sum"} {
			emitted[base+suffix] = true
		}
	}
}

type dashboard struct {
	UID         string `json:"uid"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Templating  struct {
		List []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"list"`
	} `json:"templating"`
	Panels []struct {
		ID         int    `json:"id"`
		Type       string `json:"type"`
		Title      string `json:"title"`
		Datasource *struct {
			UID string `json:"uid"`
		} `json:"datasource"`
		Targets []struct {
			Expr         string `json:"expr"`
			LegendFormat string `json:"legendFormat"`
		} `json:"targets"`
	} `json:"panels"`
}

func readDashboards(t *testing.T) map[string]dashboard {
	t.Helper()
	files, err := filepath.Glob("dashboards/*.json")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]dashboard{}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var d dashboard
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if want := strings.TrimSuffix(filepath.Base(file), ".json"); d.UID != want {
			t.Errorf("%s has the uid %q, want %q", file, d.UID, want)
		}
		out[d.UID] = d
	}
	return out
}

func TestThereIsOneDashboardForEachRole(t *testing.T) {
	var got []string
	for uid := range readDashboards(t) {
		got = append(got, uid)
	}
	sort.Strings(got)
	if want := "ipso-api ipso-runtasks ipso-webhooks ipso-worker"; strings.Join(got, " ") != want {
		t.Fatalf("dashboards %v, want %s", got, want)
	}
}

var (
	selectorPattern = regexp.MustCompile(`\{([^{}]*)\}`)
	byPattern       = regexp.MustCompile(`\bby\s*\(([^)]*)\)`)
	legendPattern   = regexp.MustCompile(`\{\{\s*([a-z_]+)\s*\}\}`)
	namePattern     = regexp.MustCompile(`\b[a-z][a-z0-9_]*_(?:bucket|count|sum)\b`)
	jobPattern      = regexp.MustCompile(`job="([^"]*)"`)
	variablePattern = regexp.MustCompile(`\$\{?[A-Za-z_]+\}?`)
	// A label of a dashboard never names an individual, whatever the data holds (ADR-0012).
	personal = regexp.MustCompile(`person|principal|author|user|login|email|actor|subject|address|^ip$`)
)

// labelsOf are the label names an expression uses: in a selector, in a by clause, and in a legend.
func labelsOf(expr, legend string) []string {
	var labels []string
	for _, m := range selectorPattern.FindAllStringSubmatch(expr, -1) {
		for _, matcher := range strings.Split(m[1], ",") {
			if name := strings.TrimSpace(strings.FieldsFunc(matcher, func(r rune) bool { return r == '=' || r == '!' || r == '~' })[0]); name != "" {
				labels = append(labels, name)
			}
		}
	}
	for _, m := range byPattern.FindAllStringSubmatch(expr, -1) {
		for _, name := range strings.Split(m[1], ",") {
			labels = append(labels, strings.TrimSpace(name))
		}
	}
	for _, m := range legendPattern.FindAllStringSubmatch(legend, -1) {
		labels = append(labels, m[1])
	}
	return labels
}

func TestDashboardsUseOnlyWhatTheCodeSends(t *testing.T) {
	allowed := map[string]bool{"job": true, "le": true}
	for _, k := range telemetry.AllowedKeys {
		allowed[strings.ReplaceAll(string(k), ".", "_")] = true
	}
	for uid, d := range readDashboards(t) {
		vars := map[string]bool{}
		for _, v := range d.Templating.List {
			vars[v.Name] = true
		}
		if !vars["datasource"] {
			t.Errorf("%s has no datasource variable", uid)
		}
		// The run task service has no tenant, so its dashboard has no tenant to choose.
		if hasTenant := vars["tenant"]; hasTenant != (uid != "ipso-runtasks") {
			t.Errorf("%s: tenant variable %v", uid, hasTenant)
		}
		ids := map[int]bool{}
		queries := 0
		for _, p := range d.Panels {
			if ids[p.ID] {
				t.Errorf("%s: panel id %d is used twice", uid, p.ID)
			}
			ids[p.ID] = true
			if p.Type == "row" {
				continue
			}
			if p.Datasource == nil || p.Datasource.UID != "${datasource}" {
				t.Errorf("%s: panel %q does not use the datasource variable", uid, p.Title)
			}
			if len(p.Targets) == 0 {
				t.Errorf("%s: panel %q has no query", uid, p.Title)
			}
			for _, target := range p.Targets {
				queries++
				where := uid + ": " + p.Title
				for _, name := range namePattern.FindAllString(target.Expr, -1) {
					if !emitted[name] {
						t.Errorf("%s: %q is not a metric the code sends", where, name)
					}
				}
				for _, label := range labelsOf(target.Expr, target.LegendFormat) {
					if !allowed[label] {
						t.Errorf("%s: the label %q is not one the code sends", where, label)
					}
					if personal.MatchString(label) {
						t.Errorf("%s: the label %q could name a person", where, label)
					}
				}
				jobs := jobPattern.FindAllStringSubmatch(target.Expr, -1)
				if len(jobs) == 0 {
					t.Errorf("%s: the query does not select its role by job: %s", where, target.Expr)
				}
				for _, job := range jobs {
					if job[1] != "ipso/"+uid {
						t.Errorf("%s: selects %q, want %q", where, job[1], "ipso/"+uid)
					}
				}
				for _, v := range variablePattern.FindAllString(target.Expr, -1) {
					switch strings.Trim(v, "${}") {
					case "tenant", "__rate_interval", "__range":
					default:
						t.Errorf("%s: the variable %s is not one the dashboard defines", where, v)
					}
				}
			}
		}
		if queries < 8 {
			t.Errorf("%s has %d queries", uid, queries)
		}
		for _, text := range []string{d.Title, d.Description} {
			if personal.MatchString(strings.ToLower(text)) {
				t.Errorf("%s: %q could name a person", uid, text)
			}
		}
	}
}
