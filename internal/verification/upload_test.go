package verification

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

const (
	hashA  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	hashB  = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	idOne  = "01M5QJ0V9EVXKR4C89XNBNT5GG"
	idTwo  = "01M6B5CJM06Z03BNN7F7GG7KCP"
	commit = "0123456789abcdef0123456789abcdef01234567"
)

// reportOf is a report in the shape the ipso CLI writes for the check, with two verdicts.
func reportOf(check string) map[string]any {
	report := map[string]any{
		"report_version": 1,
		"ipso_version":   "0.5.0",
		"evaluated_at":   "2026-11-07T10:00:00Z",
		"env":            "prod",
		"build_sha256":   hashA,
		"verdicts": []any{
			map[string]any{"decision_id": idTwo, "slug": "use-tls", "check_index": 1, "mode": "warn", "result": "pass", "violations": 0},
			map[string]any{"decision_id": idOne, "slug": "no-public-buckets", "check_index": 0, "mode": "block", "result": "fail", "violations": 3},
		},
	}
	for _, f := range kinds[check] {
		switch f.kind {
		case hashField:
			report[f.name] = hashB
		case commitField:
			report[f.name] = commit
		case pathsField:
			report[f.name] = []string{"src", "lib"}
		case versionField:
			report[f.name] = "1.2.3"
		case adapterField:
			report[f.name] = check
		}
	}
	return report
}

func bodyOf(t *testing.T, check string, mutate func(upload, report map[string]any)) []byte {
	t.Helper()
	report := reportOf(check)
	upload := map[string]any{"check": check, "report": report, "sarif_sha256": hashB}
	if mutate != nil {
		mutate(upload, report)
	}
	body, err := json.Marshal(upload)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestParseAcceptsTheReportOfEveryCheck(t *testing.T) {
	if len(kinds) != 13 {
		t.Fatalf("%d checks write a report, want 13", len(kinds))
	}
	for check := range kinds {
		t.Run(check, func(t *testing.T) {
			up, err := Parse(bodyOf(t, check, nil))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if up.Check != check || up.Env != "prod" || up.IpsoVersion != "0.5.0" || len(up.Digest) != 32 || len(up.SarifSHA256) != 32 {
				t.Errorf("upload = %+v", up)
			}
			if got := up.EvaluatedAt.Format("2006-01-02T15:04:05Z07:00"); got != "2026-11-07T10:00:00Z" {
				t.Errorf("evaluated_at = %s", got)
			}
			var evidence map[string]any
			if err := json.Unmarshal(up.Evidence, &evidence); err != nil || len(evidence) != len(kinds[check]) {
				t.Errorf("evidence = %s, %v", up.Evidence, err)
			}
			if len(up.Verdicts) != 2 || up.Verdicts[0].DecisionID != idOne || up.Verdicts[1].DecisionID != idTwo {
				t.Errorf("verdicts are not sorted by decision id: %+v", up.Verdicts)
			}
		})
	}
}

func TestAnUploadWithoutSarifIsAccepted(t *testing.T) {
	up, err := Parse(bodyOf(t, "plan", func(upload, _ map[string]any) { delete(upload, "sarif_sha256") }))
	if err != nil || up.SarifSHA256 != nil {
		t.Fatalf("Parse = %+v, %v", up, err)
	}
	empty, err := Parse(bodyOf(t, "plan", func(_, report map[string]any) { report["verdicts"] = []any{} }))
	if err != nil || len(empty.Verdicts) != 0 {
		t.Fatalf("an empty run = %+v, %v", empty, err)
	}
}

func TestTheDigestIgnoresFormattingAndOrderButNotContent(t *testing.T) {
	first, err := Parse(bodyOf(t, "semgrep", nil))
	if err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, bodyOf(t, "semgrep", func(_, report map[string]any) {
		verdicts := report["verdicts"].([]any)
		verdicts[0], verdicts[1] = verdicts[1], verdicts[0]
		report["evaluated_at"] = "2026-11-07T12:00:00+02:00"
	}), "", "  "); err != nil {
		t.Fatal(err)
	}
	same, err := Parse(pretty.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Digest, same.Digest) {
		t.Error("the same content in another layout is another upload")
	}
	for name, mutate := range map[string]func(upload, report map[string]any){
		"a verdict": func(_, report map[string]any) {
			verdictOf(report, 1)["violations"] = 4
		},
		"the env":   func(_, report map[string]any) { report["env"] = "stage" },
		"the sarif": func(upload, _ map[string]any) { upload["sarif_sha256"] = hashA },
		"a path":    func(_, report map[string]any) { report["paths"] = []string{"src"} },
	} {
		other, err := Parse(bodyOf(t, "semgrep", mutate))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Equal(first.Digest, other.Digest) {
			t.Errorf("a different %s is the same upload", name)
		}
	}
}

func verdictOf(report map[string]any, i int) map[string]any {
	return report["verdicts"].([]any)[i].(map[string]any)
}

func TestParseRefusesWhatBreaksTheContract(t *testing.T) {
	cases := map[string]func(upload, report map[string]any){
		"a tenant in the body":      func(upload, _ map[string]any) { upload["tenant_id"] = "x" },
		"a run in the body":         func(upload, _ map[string]any) { upload["run_id"] = 1 },
		"no check":                  func(upload, _ map[string]any) { delete(upload, "check") },
		"an unknown check":          func(upload, _ map[string]any) { upload["check"] = "bare" },
		"no report":                 func(upload, _ map[string]any) { delete(upload, "report") },
		"a report that is a list":   func(upload, _ map[string]any) { upload["report"] = []any{} },
		"an extra report key":       func(_, report map[string]any) { report["tenant_id"] = "x" },
		"a missing report key":      func(_, report map[string]any) { delete(report, "env") },
		"another report version":    func(_, report map[string]any) { report["report_version"] = 2 },
		"a report version as text":  func(_, report map[string]any) { report["report_version"] = "1" },
		"a time that is not one":    func(_, report map[string]any) { report["evaluated_at"] = "yesterday" },
		"an empty tool version":     func(_, report map[string]any) { report["ipso_version"] = "" },
		"a long env":                func(_, report map[string]any) { report["env"] = strings.Repeat("e", 257) },
		"a control character":       func(_, report map[string]any) { report["env"] = "pr\nod" },
		"a bidi override":           func(_, report map[string]any) { report["env"] = "pr\u202eod" },
		"an uppercase hash":         func(_, report map[string]any) { report["build_sha256"] = strings.ToUpper(hashA) },
		"a short hash":              func(_, report map[string]any) { report["build_sha256"] = "abc" },
		"a prefixed hash":           func(_, report map[string]any) { report["build_sha256"] = "sha256:" + hashA },
		"a sarif hash that is junk": func(upload, _ map[string]any) { upload["sarif_sha256"] = "xyz" },
		"null verdicts":             func(_, report map[string]any) { report["verdicts"] = nil },
		"a bad decision id":         func(_, report map[string]any) { verdictOf(report, 0)["decision_id"] = "not-a-ulid" },
		"a lowercase decision id":   func(_, report map[string]any) { verdictOf(report, 0)["decision_id"] = strings.ToLower(idOne) },
		"a bad slug":                func(_, report map[string]any) { verdictOf(report, 0)["slug"] = "Use TLS" },
		"a long slug":               func(_, report map[string]any) { verdictOf(report, 0)["slug"] = strings.Repeat("a", 129) },
		"a negative index":          func(_, report map[string]any) { verdictOf(report, 0)["check_index"] = -1 },
		"a fractional index":        func(_, report map[string]any) { verdictOf(report, 0)["check_index"] = 1.5 },
		"a bad mode":                func(_, report map[string]any) { verdictOf(report, 0)["mode"] = "block-all" },
		"a bad result":              func(_, report map[string]any) { verdictOf(report, 0)["result"] = "ok" },
		"violations on a pass":      func(_, report map[string]any) { verdictOf(report, 0)["violations"] = 1 },
		"a fail with none":          func(_, report map[string]any) { verdictOf(report, 1)["violations"] = 0 },
		"an unknown verdict field":  func(_, report map[string]any) { verdictOf(report, 0)["message"] = "x" },
		"a repeated check": func(_, report map[string]any) {
			verdictOf(report, 0)["decision_id"], verdictOf(report, 0)["check_index"] = idOne, 0
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(bodyOf(t, "plan", mutate)); !errors.Is(err, ErrInvalid) {
				t.Errorf("Parse = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestParseRefusesWhatBreaksOneChecksFields(t *testing.T) {
	cases := []struct {
		check  string
		mutate func(report map[string]any)
	}{
		{"ci", func(r map[string]any) { r["commit_sha"] = "main" }},
		{"ci", func(r map[string]any) { delete(r, "evidence_sha256") }},
		{"pulumi", func(r map[string]any) { r["adapter"] = "arm" }},
		{"arm", func(r map[string]any) { r["input_sha256"] = 1 }},
		{"depcruise", func(r map[string]any) { r["paths"] = nil }},
		{"depcruise", func(r map[string]any) { r["paths"] = []string{""} }},
		{"depcruise", func(r map[string]any) { r["paths"] = []string{"a\x00b"} }},
		{"depcruise", func(r map[string]any) { r["paths"] = []string{strings.Repeat("p", 513)} }},
		{"depcruise", func(r map[string]any) { r["paths"] = make([]string, 101) }},
		// Each backslash is two bytes of JSON, so these paths pass the per-path rule and are too much together.
		{"depcruise", func(r map[string]any) {
			paths := make([]string, 100)
			for i := range paths {
				paths[i] = strings.Repeat(`\`, 500)
			}
			r["paths"] = paths
		}},
		{"kyverno", func(r map[string]any) { r["kyverno_version"] = strings.Repeat("v", 65) }},
		{"eslint", func(r map[string]any) { r["semgrep_version"] = "1" }},
	}
	for i, c := range cases {
		_, err := Parse(bodyOf(t, c.check, func(_, report map[string]any) { c.mutate(report) }))
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d (%s): Parse = %v, want ErrInvalid", i, c.check, err)
		}
	}
	// The engine did not run, so its version is empty. That is a valid report.
	if _, err := Parse(bodyOf(t, "archunit", func(_, r map[string]any) { r["archunit_version"] = "" })); err != nil {
		t.Errorf("an empty engine version: %v", err)
	}
}

func TestParseRefusesDataThatIsNotOneObject(t *testing.T) {
	good := bodyOf(t, "plan", nil)
	for name, body := range map[string][]byte{
		"empty":           nil,
		"text":            []byte("hello"),
		"a list":          []byte("[]"),
		"two objects":     append(append([]byte{}, good...), good...),
		"trailing text":   append(append([]byte{}, good...), []byte(" x")...),
		"null":            []byte("null"),
		"a truncated one": good[:len(good)/2],
	} {
		if _, err := Parse(body); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Parse = %v, want ErrInvalid", name, err)
		}
	}
}

func TestParseBoundsTheVerdicts(t *testing.T) {
	many := func(n int) func(_, report map[string]any) {
		return func(_, report map[string]any) {
			verdicts := make([]any, n)
			for i := range verdicts {
				verdicts[i] = map[string]any{"decision_id": idOne, "slug": "use-tls", "check_index": i, "mode": "block", "result": "pass", "violations": 0}
			}
			report["verdicts"] = verdicts
		}
	}
	if up, err := Parse(bodyOf(t, "plan", many(MaxVerdicts))); err != nil || len(up.Verdicts) != MaxVerdicts {
		t.Fatalf("%d verdicts: %v", MaxVerdicts, err)
	}
	if _, err := Parse(bodyOf(t, "plan", many(MaxVerdicts+1))); !errors.Is(err, ErrInvalid) {
		t.Errorf("%d verdicts: %v, want ErrInvalid", MaxVerdicts+1, err)
	}
}

func TestAnErrorNeverQuotesWhatWasSent(t *testing.T) {
	const marker = "SECRET-MARKER-VALUE"
	for _, mutate := range []func(upload, report map[string]any){
		func(_, report map[string]any) { report["env"] = marker + "\n" },
		func(_, report map[string]any) { report["build_sha256"] = marker },
		func(_, report map[string]any) { verdictOf(report, 0)["slug"] = marker },
		func(_, report map[string]any) { verdictOf(report, 0)["mode"] = marker },
		func(upload, _ map[string]any) { upload["check"] = marker },
		func(upload, _ map[string]any) { upload[marker] = 1 },
	} {
		_, err := Parse(bodyOf(t, "plan", mutate))
		if err == nil || strings.Contains(err.Error(), marker) {
			t.Errorf("error = %v", err)
		}
	}
}

func TestAFilterIsCheckedBeforeItReachesTheDatabase(t *testing.T) {
	for _, repo := range []string{"acme/api", "ACME/API", "a-b/c_d.e"} {
		if !validRepo(strings.ToLower(repo)) {
			t.Errorf("validRepo(%q) = false", repo)
		}
	}
	for _, repo := range []string{"", "acme", "/api", "acme/", "a/b/c", "acme/ap i", "acme/api%", strings.Repeat("a", 141) + "/b"} {
		if validRepo(repo) {
			t.Errorf("validRepo(%q) = true", repo)
		}
	}
}

// The reports in testdata were written by ipso 0.4.0, from the examples of the ipso repository: a plan check
// with a passing and a failing check, and an adapter check that selected none. They show that what the CLI
// writes is what Parse reads, and not only what these tests believe the CLI writes.
func TestParseAcceptsTheReportsTheCLIWrote(t *testing.T) {
	for check, file := range map[string]string{"plan": "testdata/plan-report.json", "cloudformation": "testdata/cloudformation-report.json"} {
		report, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(map[string]any{"check": check, "report": json.RawMessage(report), "sarif_sha256": hashB})
		if err != nil {
			t.Fatal(err)
		}
		up, err := Parse(body)
		if err != nil {
			t.Fatalf("%s: %v", check, err)
		}
		if up.IpsoVersion != "0.4.0" || up.Env != "prod" || len(up.BuildSHA256) != 32 {
			t.Errorf("%s: upload = %+v", check, up)
		}
		if check == "plan" && (len(up.Verdicts) != 2 || up.Verdicts[1].Result != "fail" && up.Verdicts[0].Result != "fail") {
			t.Errorf("plan verdicts = %+v", up.Verdicts)
		}
		if check == "cloudformation" && len(up.Verdicts) != 0 {
			t.Errorf("cloudformation verdicts = %+v", up.Verdicts)
		}
	}
	// A report is for the command that wrote it. The plan report is no cloudformation report.
	report, _ := os.ReadFile("testdata/plan-report.json")
	body, _ := json.Marshal(map[string]any{"check": "cloudformation", "report": json.RawMessage(report)})
	if _, err := Parse(body); !errors.Is(err, ErrInvalid) {
		t.Errorf("a plan report as a cloudformation report: %v, want ErrInvalid", err)
	}
}
