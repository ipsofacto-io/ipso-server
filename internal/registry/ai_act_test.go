package registry

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestAIActGuardrails is the code rule of ADR-0152. Application code does not import a product
// analytics client, a verdict or proposal read does not group or order by a person, and the two
// inbox surfaces that show a model id also show the AI-generated label.
func TestAIActGuardrails(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	var analytics []string
	var keyed []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipAIActDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if aiActAnalyticsFile(rel) && analyticsClient.Match(data) {
			analytics = append(analytics, rel)
		}
		if aiActSQLFile(rel) {
			for _, clause := range orderClauses(data) {
				if personKey.Match(clause) {
					keyed = append(keyed, rel)
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(analytics) != 0 {
		t.Errorf("product analytics client in %v", analytics)
	}
	if len(keyed) != 0 {
		t.Errorf("verdict or proposal read grouped or ordered by a person in %v", keyed)
	}
	checkInboxLabel(t, filepath.Join(root, "web", "src", "views", "Inbox.tsx"))
}

func skipAIActDir(name string) bool {
	switch name {
	case ".git", "node_modules", "dist", "testdata", "pgtest", "migrations", "vendor":
		return true
	default:
		return false
	}
}

func aiActAnalyticsFile(rel string) bool {
	switch {
	case strings.HasSuffix(rel, ".go"):
		return true
	case strings.HasPrefix(rel, "web/src/") && (strings.HasSuffix(rel, ".ts") || strings.HasSuffix(rel, ".tsx")):
		return true
	case rel == "go.mod" || rel == "web/package.json":
		return true
	default:
		return false
	}
}

// aiActSQLFile is a verdict or proposal read. Identity, role bindings, and SCIM stay out: the
// audit log of person writes is a security record, not a product metric (ADR-0152).
func aiActSQLFile(rel string) bool {
	if !strings.HasSuffix(rel, ".go") || strings.Contains(rel, "/identity/") {
		return false
	}
	return strings.HasPrefix(rel, "internal/") || strings.HasPrefix(rel, "trackers/") || strings.HasPrefix(rel, "chat/")
}

var (
	analyticsClient = regexp.MustCompile(`(?i)(\bposthog\b|\bplausible\b|\bmixpanel\b|\bamplitude\b|segmentio/analytics|@segment/|\bumami\b)`)
	orderBy         = regexp.MustCompile("(?is)\\b(?:group|order)\\s+by\\s+([^;`]{0,300})")
	personKey       = regexp.MustCompile(`(?i)\b(?:principal(?:_id)?|author(?:_[a-z]+)?|person(?:_[a-z]+)?)\b`)
)

func orderClauses(src []byte) [][]byte {
	found := orderBy.FindAllSubmatch(src, -1)
	out := make([][]byte, 0, len(found))
	for _, match := range found {
		if len(match) > 1 {
			out = append(out, match[1])
		}
	}
	return out
}

func checkInboxLabel(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	src := string(data)
	label := functionSource(t, src, "ModelLabel")
	if !strings.Contains(label, "AI-generated") || !strings.Contains(label, "modelID") || !strings.Contains(label, "promptVersion") {
		t.Errorf("ModelLabel must show AI-generated with the model id and the prompt version")
	}
	note := functionSource(t, src, "Advisory")
	const sentence = "A person approves it, and it does not block a merge."
	if !strings.Contains(note, sentence) && !strings.Contains(src, "const advisory = '"+sentence+"'") {
		t.Errorf("the advisory sentence is missing")
	}
	for _, name := range []string{"PullRequest", "DraftedCheck"} {
		body := functionSource(t, src, name)
		if !strings.Contains(body, "<ModelLabel") || !strings.Contains(body, "model_id") || !strings.Contains(body, "prompt_version") || !strings.Contains(body, "<Advisory") {
			t.Errorf("%s must label the model draft and say it does not block", name)
		}
	}
	agent := functionSource(t, src, "FromAgent")
	if strings.Contains(agent, "ModelLabel") || strings.Contains(agent, "model_id") || strings.Contains(agent, "AI-generated") {
		t.Errorf("a coding-agent proposal has no model id and must not carry the model label")
	}
}

func functionSource(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, "function "+name+"(")
	if start < 0 {
		t.Fatalf("function %s is missing", name)
	}
	rest := src[start+1:]
	next := strings.Index(rest, "\nfunction ")
	if next < 0 {
		return src[start:]
	}
	return src[start : start+1+next]
}
