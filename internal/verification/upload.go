// Package verification stores the verdicts a CI job uploads and reads them back (ADR-0102). An upload
// is the ADR-0030 verdict report of one check, plus the digest of the SARIF file it wrote, and nothing
// else: plan values, resource addresses, violation messages and SARIF stay in the runner (ADR-0006).
//
// The package knows no HTTP. The tenant and the run come from the caller, which took them from a
// verified CI token and the installation mapping, and nothing in the body names either.
package verification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ErrInvalid is returned for an upload or a filter that does not meet the contract. The message names
// the field and the rule, and never quotes the value, because an upload comes from a runner.
var ErrInvalid = errors.New("invalid")

const (
	// MaxVerdicts bounds the verdicts of one upload. A repository has far fewer decision checks, and the
	// body cap of the API bounds the bytes.
	MaxVerdicts = 5000
	// reportVersion is the only ADR-0030 report version.
	reportVersion = 1
	maxPaths      = 100
	maxPathBytes  = 512
	maxTextBytes  = 64
	maxEnvBytes   = 256
	maxSlugBytes  = 128
	maxCheckIndex = 1 << 20
	maxViolations = 1<<31 - 1
	// maxEvidenceBytes bounds the JSON of the fields only some reports have. The table caps it at 64 KiB, and
	// this is half of that, because the JSON of a path doubles when every character needs an escape.
	maxEvidenceBytes = 32 << 10
)

var (
	hexDigits   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitSHA   = regexp.MustCompile(`^[0-9a-f]{40}$|^[0-9a-f]{64}$`)
	decisionID  = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	decisionRef = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
)

// fieldKind says how a field of a report is read.
type fieldKind int

const (
	hashField fieldKind = iota
	commitField
	pathsField
	versionField
	adapterField
)

type field struct {
	name string
	kind fieldKind
}

// commonKeys are the keys every report has.
var commonKeys = []string{"report_version", "ipso_version", "evaluated_at", "env", "build_sha256", "verdicts"}

// kinds is the closed list of checks that write a report, with the keys only that report has. They are
// the Report types of internal/compiler in the ipso CLI.
var kinds = map[string][]field{
	"plan":           {{"plan_sha256", hashField}},
	"ci":             {{"commit_sha", commitField}, {"evidence_sha256", hashField}},
	"checkov":        {{"evidence_sha256", hashField}},
	"pulumi":         {{"adapter", adapterField}, {"input_sha256", hashField}},
	"cloudformation": {{"adapter", adapterField}, {"input_sha256", hashField}},
	"arm":            {{"adapter", adapterField}, {"input_sha256", hashField}},
	"depcruise":      {{"paths", pathsField}, {"depcruise_version", versionField}},
	"semgrep":        {{"paths", pathsField}, {"semgrep_version", versionField}},
	"archunit":       {{"paths", pathsField}, {"archunit_version", versionField}},
	"importlinter":   {{"paths", pathsField}, {"importlinter_version", versionField}},
	"kyverno":        {{"paths", pathsField}, {"kyverno_version", versionField}},
	"gatekeeper":     {{"paths", pathsField}, {"gator_version", versionField}},
	"eslint":         {{"paths", pathsField}, {"eslint_version", versionField}},
}

// Verdict is the outcome of one decision check, as the report states it.
type Verdict struct {
	DecisionID string `json:"decision_id"`
	Slug       string `json:"slug"`
	CheckIndex int    `json:"check_index"`
	Mode       string `json:"mode"`
	Result     string `json:"result"`
	Violations int    `json:"violations"`
}

// Upload is a validated upload. Parse is the only way to make one, so every field has met its rule.
type Upload struct {
	Check       string
	Env         string
	IpsoVersion string
	EvaluatedAt time.Time
	BuildSHA256 []byte
	// SarifSHA256 is the digest of the SARIF file the same command wrote, or nil.
	SarifSHA256 []byte
	// Evidence is the JSON object of the fields only this check's report has.
	Evidence json.RawMessage
	// Verdicts are in the order of decision id, then check index.
	Verdicts []Verdict
	// Digest is the sha256 of the canonical form of the upload. The same run, attempt and digest is one
	// upload, so a repeat adds nothing.
	Digest []byte
}

type envelope struct {
	Check       string          `json:"check"`
	Report      json.RawMessage `json:"report"`
	SarifSHA256 *string         `json:"sarif_sha256"`
}

// Parse reads the body of an upload. It is strict: an unknown field, a missing one, a value outside its
// rule and data after the object are all errors. The body has no tenant or run field to ignore.
func Parse(body []byte) (Upload, error) {
	var env envelope
	if err := decodeStrict(body, &env); err != nil {
		return Upload{}, invalid("the body is not an upload object")
	}
	fields, ok := kinds[env.Check]
	if !ok {
		return Upload{}, invalid("check is not a check that writes a report")
	}
	var report map[string]json.RawMessage
	if err := decodeStrict(env.Report, &report); err != nil {
		return Upload{}, invalid("report is not an object")
	}
	want := slices.Clone(commonKeys)
	for _, f := range fields {
		want = append(want, f.name)
	}
	if len(report) != len(want) {
		return Upload{}, invalid("report does not have exactly the keys of this check")
	}
	for _, key := range want {
		if _, ok := report[key]; !ok {
			return Upload{}, invalid("report does not have exactly the keys of this check")
		}
	}

	up := Upload{Check: env.Check}
	var version int
	if err := decodeStrict(report["report_version"], &version); err != nil || version != reportVersion {
		return Upload{}, invalid("report_version is not 1")
	}
	var evaluated string
	if err := decodeStrict(report["evaluated_at"], &evaluated); err != nil {
		return Upload{}, invalid("evaluated_at is not a time")
	}
	at, err := time.Parse(time.RFC3339, evaluated)
	if err != nil {
		return Upload{}, invalid("evaluated_at is not an RFC 3339 time")
	}
	up.EvaluatedAt = at.UTC()
	if err := readText(report["ipso_version"], &up.IpsoVersion, 1, maxTextBytes); err != nil {
		return Upload{}, invalid("ipso_version is not a short text")
	}
	if err := readText(report["env"], &up.Env, 0, maxEnvBytes); err != nil {
		return Upload{}, invalid("env is not a short text")
	}
	if up.BuildSHA256, err = readHash(report["build_sha256"]); err != nil {
		return Upload{}, invalid("build_sha256 is not a lowercase sha256")
	}
	if env.SarifSHA256 != nil {
		if !hexDigits.MatchString(*env.SarifSHA256) {
			return Upload{}, invalid("sarif_sha256 is not a lowercase sha256")
		}
		up.SarifSHA256, _ = hex.DecodeString(*env.SarifSHA256)
	}
	if up.Evidence, err = readEvidence(env.Check, fields, report); err != nil {
		return Upload{}, err
	}
	if up.Verdicts, err = readVerdicts(report["verdicts"]); err != nil {
		return Upload{}, err
	}
	up.Digest = digest(up)
	return up, nil
}

func readEvidence(check string, fields []field, report map[string]json.RawMessage) (json.RawMessage, error) {
	evidence := make(map[string]any, len(fields))
	for _, f := range fields {
		raw := report[f.name]
		switch f.kind {
		case hashField:
			sum, err := readHash(raw)
			if err != nil {
				return nil, invalid(f.name + " is not a lowercase sha256")
			}
			evidence[f.name] = hex.EncodeToString(sum)
		case commitField:
			var sha string
			if err := decodeStrict(raw, &sha); err != nil || !commitSHA.MatchString(sha) {
				return nil, invalid(f.name + " is not a commit sha")
			}
			evidence[f.name] = sha
		case versionField:
			var text string
			if err := readText(raw, &text, 0, maxTextBytes); err != nil {
				return nil, invalid(f.name + " is not a short text")
			}
			evidence[f.name] = text
		case adapterField:
			var name string
			if err := decodeStrict(raw, &name); err != nil || name != check {
				return nil, invalid(f.name + " is not the adapter of this check")
			}
			evidence[f.name] = name
		case pathsField:
			var paths []string
			if err := decodeStrict(raw, &paths); err != nil || paths == nil || len(paths) > maxPaths {
				return nil, invalid(f.name + " is not a short list of paths")
			}
			for _, path := range paths {
				if !plain(path, 1, maxPathBytes) {
					return nil, invalid(f.name + " has a path that is not a short text")
				}
			}
			evidence[f.name] = paths
		}
	}
	encoded, err := json.Marshal(evidence)
	if err != nil || len(encoded) > maxEvidenceBytes {
		return nil, invalid("the report fields of this check are too large")
	}
	return encoded, nil
}

func readVerdicts(raw json.RawMessage) ([]Verdict, error) {
	var verdicts []Verdict
	if err := decodeStrict(raw, &verdicts); err != nil || verdicts == nil {
		return nil, invalid("verdicts is not a list of verdicts")
	}
	if len(verdicts) > MaxVerdicts {
		return nil, invalid("verdicts has more than the allowed number")
	}
	type key struct {
		decision string
		index    int
	}
	seen := make(map[key]bool, len(verdicts))
	for _, v := range verdicts {
		switch {
		case !decisionID.MatchString(v.DecisionID):
			return nil, invalid("a verdict has a decision_id that is not an EDR id")
		case len(v.Slug) < 1 || len(v.Slug) > maxSlugBytes || !decisionRef.MatchString(v.Slug):
			return nil, invalid("a verdict has a slug that is not an EDR slug")
		case v.CheckIndex < 0 || v.CheckIndex >= maxCheckIndex:
			return nil, invalid("a verdict has a check_index out of range")
		case v.Mode != "block" && v.Mode != "warn" && v.Mode != "advise":
			return nil, invalid("a verdict has a mode that is not block, warn or advise")
		case v.Result != "pass" && v.Result != "fail" && v.Result != "waived" && v.Result != "error":
			return nil, invalid("a verdict has a result that is not pass, fail, waived or error")
		case (v.Result == "pass" || v.Result == "error") && v.Violations != 0:
			return nil, invalid("a verdict with no denial has violations")
		case (v.Result == "fail" || v.Result == "waived") && (v.Violations < 1 || v.Violations > maxViolations):
			return nil, invalid("a verdict with a denial has no violations or too many")
		}
		k := key{v.DecisionID, v.CheckIndex}
		if seen[k] {
			return nil, invalid("two verdicts have the same decision_id and check_index")
		}
		seen[k] = true
	}
	slices.SortFunc(verdicts, func(a, b Verdict) int {
		if c := strings.Compare(a.DecisionID, b.DecisionID); c != 0 {
			return c
		}
		return a.CheckIndex - b.CheckIndex
	})
	return verdicts, nil
}

// digest is the sha256 of the upload as the server would write it again: fixed key order, the verdicts
// sorted, the time in UTC. Reformatting a report therefore does not make it a different upload.
func digest(up Upload) []byte {
	canonical, _ := json.Marshal(struct {
		Check       string          `json:"check"`
		Env         string          `json:"env"`
		IpsoVersion string          `json:"ipso_version"`
		EvaluatedAt string          `json:"evaluated_at"`
		BuildSHA256 string          `json:"build_sha256"`
		SarifSHA256 string          `json:"sarif_sha256"`
		Evidence    json.RawMessage `json:"evidence"`
		Verdicts    []Verdict       `json:"verdicts"`
	}{
		up.Check, up.Env, up.IpsoVersion, up.EvaluatedAt.Format(time.RFC3339Nano),
		hex.EncodeToString(up.BuildSHA256), hex.EncodeToString(up.SarifSHA256), up.Evidence, up.Verdicts,
	})
	sum := sha256.Sum256(canonical)
	return sum[:]
}

// decodeStrict decodes one JSON value into out and refuses an unknown field and any data after it.
func decodeStrict(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the value")
	}
	return nil
}

func readText(raw json.RawMessage, out *string, minBytes, maxBytes int) error {
	var text string
	if err := decodeStrict(raw, &text); err != nil || !plain(text, minBytes, maxBytes) {
		return ErrInvalid
	}
	*out = text
	return nil
}

func readHash(raw json.RawMessage) ([]byte, error) {
	var text string
	if err := decodeStrict(raw, &text); err != nil || !hexDigits.MatchString(text) {
		return nil, ErrInvalid
	}
	return hex.DecodeString(text)
}

// plain holds for valid UTF-8 of minBytes to maxBytes with no control or format character, so a name
// from a runner cannot reorder or hide text where a person reads it.
func plain(text string, minBytes, maxBytes int) bool {
	if len(text) < minBytes || len(text) > maxBytes || !utf8.ValidString(text) {
		return false
	}
	for _, r := range text {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func invalid(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalid, reason)
}
