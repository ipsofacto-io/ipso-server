package proposals

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ipsofacto-io/ipso-server/internal/redact"
	"github.com/ipsofacto-io/ipso-server/internal/verification"
)

const (
	// AdvisoryPromptVersion names the prompt an advisory verdict was made with (ADR-0173).
	AdvisoryPromptVersion = "pr-advisory-v2"
	// maxAdvisoryTokens bounds an answer of three keys, ten hunk numbers and a reason of 300 runes.
	maxAdvisoryTokens = 256
	// MaxAdvisoryHunks is the most hunks one check sends. A check that would send more is skipped.
	MaxAdvisoryHunks = 20
	// maxAdvisoryMessageBytes bounds the JSON sent for one check, so that it fits the 8192-token context of
	// the local route with the prompt and the answer (ADR-0173).
	maxAdvisoryMessageBytes = 12 << 10
	// MaxCheckPromptRunes bounds the check prompt file a check names, and the title and the statement bound
	// what the model reads of the decision.
	MaxCheckPromptRunes       = 2000
	maxAdvisoryTitleRunes     = 200
	maxAdvisoryStatementRunes = 2000
	// maxModelIDBytes is the longest model id a verdict keeps.
	maxModelIDBytes = 200
)

//go:embed prompts/pr-advisory-v2.txt
var advisoryPrompt string

var (
	// ErrAdvisoryRequest means a check cannot be sent as it is: a patch does not match its own counts, a
	// file is one ipso never sends, or the check holds too many hunks or too much text. The check is skipped.
	ErrAdvisoryRequest = errors.New("the check cannot be sent")
	// ErrAdvisoryAnswer means the answer is not the one object the prompt asks for. Nothing from it is stored.
	ErrAdvisoryAnswer = errors.New("the answer is not an advisory verdict")
)

// hunkHeader is the first line of one hunk of a unified diff. A count left out is one.
var hunkHeader = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

// checkPromptRef is the grammar EDR 1.1 gives the ref of an engine: llm check, which an llm-advisory check
// names a prompt file with: segments of letters, digits, dots, dashes and underscores, none of them . or ..
var checkPromptRef = regexp.MustCompile(`^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$`)

// sshKeyName is the name of an SSH key file, such as id_rsa or id_ed25519, which has no extension.
var sshKeyName = regexp.MustCompile(`^id_[A-Za-z0-9_-]+$`)

// Hunk is one hunk of the patch of one file, as GitHub sent it. Text is the hunk with its header, before
// redaction. StartLine and EndLine are the lines on the head side that the hunk added, or the line after
// which it removed lines when it added none, so a verdict that cites it names a place on the head commit.
type Hunk struct {
	Path      string
	Text      string
	StartLine int
	EndLine   int
}

// ValidCheckPromptRef reports whether ref can name a check prompt file.
func ValidCheckPromptRef(ref string) bool {
	if len(ref) > 255 || !checkPromptRef.MatchString(ref) {
		return false
	}
	for _, segment := range strings.Split(ref, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// NeverSent reports whether a file is one whose diff ipso never sends to a model, because it usually holds a
// secret or says who owns the code: an env file, a key or certificate, an SSH key, or CODEOWNERS (ADR-0173).
// The name is compared without its directory. A path that redaction would change, such as one that holds an
// email address, is never sent either, so a place a verdict stores is always a path the model was shown.
func NeverSent(file string) bool {
	name := path.Base(file)
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, ".env") || strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".key") ||
		sshKeyName.MatchString(name) || name == "CODEOWNERS" || redact.Text(file) != file
}

// ParsePatch splits the patch GitHub keeps for one file into its hunks. Each hunk must hold exactly the
// lines its header counts, so a patch GitHub cut short, or text that only looks like a diff, is
// ErrAdvisoryRequest and is not sent.
func ParsePatch(file, patch string) ([]Hunk, error) {
	patch = strings.TrimSuffix(patch, "\n")
	if patch == "" {
		return nil, nil
	}
	lines := strings.Split(patch, "\n")
	var hunks []Hunk
	for i := 0; i < len(lines); {
		match := hunkHeader.FindStringSubmatch(lines[i])
		if match == nil {
			return nil, fmt.Errorf("%w: a hunk of %s has no header", ErrAdvisoryRequest, file)
		}
		oldLeft, newStart, newLeft := count(match[2]), number(match[3]), count(match[4])
		if oldLeft < 0 || newStart < 0 || newLeft < 0 {
			return nil, fmt.Errorf("%w: a hunk header of %s is out of range", ErrAdvisoryRequest, file)
		}
		start := i
		i++
		line, first, last, removedAfter := newStart, 0, 0, -1
		for i < len(lines) && (oldLeft > 0 || newLeft > 0 || strings.HasPrefix(lines[i], `\`)) {
			text := lines[i]
			switch {
			case strings.HasPrefix(text, `\`):
			case strings.HasPrefix(text, "+"):
				if newLeft == 0 {
					return nil, fmt.Errorf("%w: a hunk of %s adds more lines than it counts", ErrAdvisoryRequest, file)
				}
				if first == 0 {
					first = line
				}
				last = line
				line++
				newLeft--
			case strings.HasPrefix(text, "-"):
				if oldLeft == 0 {
					return nil, fmt.Errorf("%w: a hunk of %s removes more lines than it counts", ErrAdvisoryRequest, file)
				}
				if removedAfter < 0 {
					removedAfter = line - 1
				}
				oldLeft--
			case text == "" || strings.HasPrefix(text, " "):
				if oldLeft == 0 || newLeft == 0 {
					return nil, fmt.Errorf("%w: a hunk of %s holds more context than it counts", ErrAdvisoryRequest, file)
				}
				line++
				oldLeft--
				newLeft--
			default:
				return nil, fmt.Errorf("%w: a hunk of %s holds a line that is not a diff line", ErrAdvisoryRequest, file)
			}
			i++
		}
		if oldLeft > 0 || newLeft > 0 {
			return nil, fmt.Errorf("%w: a hunk of %s ends before its counts", ErrAdvisoryRequest, file)
		}
		hunk := Hunk{Path: file, Text: strings.Join(lines[start:i], "\n"), StartLine: first, EndLine: last}
		if first == 0 {
			// A hunk that only removes lines names the line after which they were removed.
			at := max(removedAfter, newStart, 1)
			if removedAfter >= 0 {
				at = max(removedAfter, 1)
			}
			hunk.StartLine, hunk.EndLine = at, at
		}
		hunks = append(hunks, hunk)
	}
	return hunks, nil
}

// count reads the count of a hunk header, which is one when the header leaves it out.
func count(text string) int {
	if text == "" {
		return 1
	}
	return number(text)
}

// number reads a line number of a hunk header, or -1 when it is not one ipso reads.
func number(text string) int {
	n, err := strconv.Atoi(text)
	if err != nil || n > 1<<24 {
		return -1
	}
	return n
}

// AdvisoryRequest is one llm-advisory check of one decision, and the hunks of the files in its scope.
// CheckPrompt is the text of the prompt file the check names, or empty when it names none.
type AdvisoryRequest struct {
	Title       string
	Statement   string
	CheckPrompt string
	Hunks       []Hunk
}

// PreparedAdvisory is a request as it will be sent: the JSON the model reads, and its digest. The digest
// leaves out the random markers of the call, so the same hunks and the same decision text give the same
// digest on another head, and the answer can be reused (ADR-0173).
type PreparedAdvisory struct {
	payload []byte
	hunks   []Hunk
	Input   [32]byte
}

type shownHunk struct {
	N    int    `json:"n"`
	Path string `json:"path"`
	Diff string `json:"diff"`
}

// PrepareAdvisory redacts and encodes a request. The diff and the path go through redact.Text, which keeps
// code readable, and the decision text through Redact. A request with no hunk, more than MaxAdvisoryHunks,
// a check prompt longer than MaxCheckPromptRunes, or an encoding over 12 KiB is ErrAdvisoryRequest.
func PrepareAdvisory(req AdvisoryRequest) (PreparedAdvisory, error) {
	switch {
	case strings.TrimSpace(req.Title) == "":
		return PreparedAdvisory{}, fmt.Errorf("%w: the decision has no title", ErrAdvisoryRequest)
	case len(req.Hunks) == 0:
		return PreparedAdvisory{}, fmt.Errorf("%w: no hunk", ErrAdvisoryRequest)
	case len(req.Hunks) > MaxAdvisoryHunks:
		return PreparedAdvisory{}, fmt.Errorf("%w: more than %d hunks", ErrAdvisoryRequest, MaxAdvisoryHunks)
	case !utf8.ValidString(req.CheckPrompt) || utf8.RuneCountInString(req.CheckPrompt) > MaxCheckPromptRunes:
		return PreparedAdvisory{}, fmt.Errorf("%w: the check prompt is not text of at most %d runes", ErrAdvisoryRequest, MaxCheckPromptRunes)
	}
	type decisionText struct {
		Title       string `json:"title"`
		Statement   string `json:"statement"`
		CheckPrompt string `json:"check_prompt,omitempty"`
	}
	shown := make([]shownHunk, len(req.Hunks))
	for i, hunk := range req.Hunks {
		shown[i] = shownHunk{N: i + 1, Path: redact.Text(hunk.Path), Diff: redact.Text(hunk.Text)}
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(struct {
		Decision decisionText `json:"decision"`
		Hunks    []shownHunk  `json:"hunks"`
	}{
		Decision: decisionText{
			Title:       truncate(Redact(req.Title), maxAdvisoryTitleRunes),
			Statement:   truncate(Redact(req.Statement), maxAdvisoryStatementRunes),
			CheckPrompt: Redact(req.CheckPrompt),
		},
		Hunks: shown,
	}); err != nil {
		return PreparedAdvisory{}, err
	}
	payload := bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
	if len(payload) > maxAdvisoryMessageBytes {
		return PreparedAdvisory{}, fmt.Errorf("%w: the check is over %d bytes", ErrAdvisoryRequest, maxAdvisoryMessageBytes)
	}
	return PreparedAdvisory{payload: payload, hunks: req.Hunks, Input: sha256.Sum256(payload)}, nil
}

// Flagged counts the hunks whose text addresses a model or hides characters from a reader. Nothing is
// dropped for it: the data markers, the canary, the fixed answer shape and the server-built places are
// what keep such text from changing a verdict, and the count says how often a change tries.
func (p PreparedAdvisory) Flagged() int {
	n := 0
	for _, hunk := range p.hunks {
		if suspicious(hunk.Text) {
			n++
		}
	}
	return n
}

// AdvisoryAnswer is what the model said about one check, checked. Cited holds the places of the hunks the
// answer named, built from the hunks the server sent, never from the answer text.
type AdvisoryAnswer struct {
	Assessment    string
	Cited         []verification.Place
	Reason        string
	Model         string
	PromptVersion string
}

// Advise sends a prepared check to the model and checks the answer. The answer must be one object with the
// keys assessment, hunks and reason, each once, whatever schema the route applied, and nothing after it. The
// hunk numbers must be distinct, within the hunks sent and at most ten, and a deviates answer must cite one.
// The reason must be plain text of 1 to 300 runes. An answer that repeats the canary obeyed the data, and an
// answer with no model id cannot be attributed, so both are refused. Every refusal is ErrAdvisoryAnswer and
// keeps nothing. There is no repair round. The decision, the check, the result and the mode never come from
// the answer, so injected text cannot change which decision a verdict is about or make it block.
func Advise(ctx context.Context, complete SchemaCompleteFunc, prepared PreparedAdvisory) (AdvisoryAnswer, error) {
	if len(prepared.payload) == 0 || len(prepared.hunks) == 0 {
		return AdvisoryAnswer{}, fmt.Errorf("%w: the check was not prepared", ErrAdvisoryRequest)
	}
	nonce, err := randomHex()
	if err != nil {
		return AdvisoryAnswer{}, err
	}
	canary, err := randomHex()
	if err != nil {
		return AdvisoryAnswer{}, err
	}
	marker := "DATA-" + nonce
	user := marker + "\n" + string(prepared.payload) + "\n" + marker
	answer, err := complete(ctx, advisoryPrompt+" CANARY-"+canary+"\n", user, maxAdvisoryTokens, advisorySchema)
	if err != nil {
		return AdvisoryAnswer{}, err
	}
	if strings.Contains(strings.ToLower(answer.Text), canary[:16]) {
		return AdvisoryAnswer{}, fmt.Errorf("%w: it repeats the secret marker", ErrAdvisoryAnswer)
	}
	parsed, err := parseAdvisory(answer.Text, len(prepared.hunks))
	if err != nil {
		return AdvisoryAnswer{}, fmt.Errorf("%w: %w", ErrAdvisoryAnswer, err)
	}
	if strings.TrimSpace(answer.Model) == "" || len(answer.Model) > maxModelIDBytes || strings.IndexFunc(answer.Model, unicode.IsControl) >= 0 {
		return AdvisoryAnswer{}, fmt.Errorf("%w: it names no model id the verdict can keep", ErrAdvisoryAnswer)
	}
	out := AdvisoryAnswer{Assessment: parsed.assessment, Reason: parsed.reason, Model: answer.Model, PromptVersion: AdvisoryPromptVersion}
	for _, n := range parsed.hunks {
		hunk := prepared.hunks[n-1]
		out.Cited = append(out.Cited, verification.Place{Path: hunk.Path, StartLine: hunk.StartLine, EndLine: hunk.EndLine})
	}
	return out, nil
}

// advisorySchema uses only type, enum, items, required and additionalProperties, which every route applies.
// Its properties are in the order the prompt asks the model to write them: a model that writes the
// assessment first decides before it has said why, and its reason then contradicts it. The text is written
// out because a Go map would put the keys in alphabetical order.
var advisorySchema = json.RawMessage(fmt.Sprintf(
	`{"type":"object","properties":{"reason":{"type":"string"},"assessment":{"type":"string","enum":[%q,%q,%q]},"hunks":{"type":"array","items":{"type":"integer"}}},"required":["reason","assessment","hunks"],"additionalProperties":false}`,
	verification.Complies, verification.Deviates, verification.Unclear))

type advisoryParsed struct {
	assessment string
	hunks      []int
	reason     string
}

// parseAdvisory reads the answer by hand, so a repeated key, a key of another name, a number that is not a
// whole hunk number, or trailing text is refused rather than merged by a decoder.
func parseAdvisory(text string, sent int) (advisoryParsed, error) {
	if len(text) > maxOutputBytes {
		return advisoryParsed{}, errors.New("the answer is too large")
	}
	decoder := json.NewDecoder(strings.NewReader(unfence(text)))
	decoder.UseNumber()
	if err := delim(decoder, '{'); err != nil {
		return advisoryParsed{}, err
	}
	var out advisoryParsed
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return advisoryParsed{}, err
		}
		key, _ := token.(string)
		if seen[key] {
			return advisoryParsed{}, fmt.Errorf("the key %q is repeated", key)
		}
		seen[key] = true
		switch key {
		case "assessment":
			if err := decoder.Decode(&out.assessment); err != nil {
				return advisoryParsed{}, errors.New("the assessment is not a word")
			}
			if out.assessment != verification.Complies && out.assessment != verification.Deviates && out.assessment != verification.Unclear {
				return advisoryParsed{}, errors.New("the assessment is not complies, deviates or unclear")
			}
		case "hunks":
			if out.hunks, err = hunkNumbers(decoder, sent); err != nil {
				return advisoryParsed{}, err
			}
		case "reason":
			if err := decoder.Decode(&out.reason); err != nil {
				return advisoryParsed{}, errors.New("the reason is not a string")
			}
		default:
			return advisoryParsed{}, fmt.Errorf("the key %q is not asked for", key)
		}
	}
	if err := delim(decoder, '}'); err != nil {
		return advisoryParsed{}, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return advisoryParsed{}, errors.New("it holds more than one JSON value")
	}
	switch {
	case len(seen) != 3:
		return advisoryParsed{}, errors.New("it does not hold assessment, hunks and reason")
	case out.assessment == verification.Deviates && len(out.hunks) == 0:
		return advisoryParsed{}, errors.New("a deviation cites no hunk")
	case out.reason == "" || utf8.RuneCountInString(out.reason) > verification.MaxReasonRunes || !plainField(out.reason) || strings.ContainsAny(out.reason, "\n\r\t"):
		return advisoryParsed{}, errors.New("the reason is not one plain sentence of at most 300 runes")
	}
	return out, nil
}

// hunkNumbers reads an array of distinct whole numbers from 1 to sent, at most verification.MaxCited.
func hunkNumbers(decoder *json.Decoder, sent int) ([]int, error) {
	if err := delim(decoder, '['); err != nil {
		return nil, errors.New("the hunks are not an array")
	}
	var out []int
	seen := map[int]bool{}
	for decoder.More() {
		// Token and not Decode: a json.Number would also take a number written as a string.
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		raw, ok := token.(json.Number)
		if !ok {
			return nil, errors.New("a hunk is not a number")
		}
		n, err := strconv.Atoi(raw.String())
		if err != nil || n < 1 || n > sent {
			return nil, errors.New("a hunk is not the number of a hunk sent")
		}
		if seen[n] {
			return nil, errors.New("a hunk is cited twice")
		}
		seen[n] = true
		out = append(out, n)
		if len(out) > verification.MaxCited {
			return nil, errors.New("it cites too many hunks")
		}
	}
	if err := delim(decoder, ']'); err != nil {
		return nil, err
	}
	return out, nil
}
