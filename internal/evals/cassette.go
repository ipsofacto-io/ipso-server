package evals

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/ipsofacto-io/ipso-server/internal/llmgw"
)

// CompleteFunc is the shape every pipeline takes for the LLM.
type CompleteFunc func(ctx context.Context, system, user string, maxTokens int) (llmgw.Completion, error)

// SchemaCompleteFunc is CompleteFunc with the JSON schema the answer must follow.
type SchemaCompleteFunc func(ctx context.Context, system, user string, maxTokens int, schema json.RawMessage) (llmgw.Completion, error)

// ErrNotRecorded means a prompt has no recorded answer. A prompt, a dataset, or the code that
// builds the prompt changed, so the answers have to be recorded again.
var ErrNotRecorded = errors.New("no recorded answer for this prompt; record again with -record")

// Recording is one model answer. Prompt is the prompt's Key.
type Recording struct {
	Prompt string `json:"prompt_sha256"`
	Model  string `json:"model"`
	Text   string `json:"text"`
}

// Cassette answers from recordings. With a live function it records instead: each prompt is sent
// once and its answer kept, and Save writes only the answers this run used.
type Cassette struct {
	mu       sync.Mutex
	recorded map[string]Recording
	used     map[string]Recording
	live     SchemaCompleteFunc
}

// LoadCassette reads recordings. A missing file is an empty cassette.
func LoadCassette(path string) (*Cassette, error) {
	c := &Cassette{recorded: map[string]Recording{}, used: map[string]Recording{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	var recordings []Recording
	if err := json.Unmarshal(raw, &recordings); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, r := range recordings {
		c.recorded[r.Prompt] = r
	}
	return c, nil
}

// Record makes the cassette call live for every prompt.
func (c *Cassette) Record(live SchemaCompleteFunc) {
	c.live = live
}

// Complete answers one prompt with no schema.
func (c *Cassette) Complete(ctx context.Context, system, user string, maxTokens int) (llmgw.Completion, error) {
	return c.CompleteSchema(ctx, system, user, maxTokens, nil)
}

// CompleteSchema answers one prompt. A schema is part of the key, because it changes the answer.
// During live recording, random CANARY and outer DATA markers are replaced with deterministic
// per-prompt hex digests so BPE tokenization stays stable across runs, while any leaked canary in
// the answer is mapped back to the caller's canary in both modes.
func (c *Cassette) CompleteSchema(ctx context.Context, system, user string, maxTokens int, schema json.RawMessage) (llmgw.Completion, error) {
	key := Key(system, user)
	if schema != nil {
		sum := sha256.Sum256([]byte(key + "\x00" + string(schema)))
		key = hex.EncodeToString(sum[:])
	}
	var callerCanary string
	if m := promptCanary.FindStringSubmatch(system); m != nil {
		callerCanary = m[1]
	}
	fixedCanary := evalMarker("canary", key)

	c.mu.Lock()
	defer c.mu.Unlock()
	if r, ok := c.used[key]; ok {
		return llmgw.Completion{Text: restoreCanary(r.Text, fixedCanary, callerCanary), Model: r.Model}, nil
	}
	if c.live == nil {
		r, ok := c.recorded[key]
		if !ok {
			return llmgw.Completion{}, fmt.Errorf("%w (key %s)", ErrNotRecorded, key[:12])
		}
		c.used[key] = r
		return llmgw.Completion{Text: restoreCanary(r.Text, fixedCanary, callerCanary), Model: r.Model}, nil
	}
	liveSystem := system
	if callerCanary != "" {
		liveSystem = strings.ReplaceAll(system, "CANARY-"+callerCanary, "CANARY-"+fixedCanary)
	}
	liveUser := normalizeUser(user, key)
	answer, err := c.live(ctx, liveSystem, liveUser, maxTokens, schema)
	if err != nil {
		return llmgw.Completion{}, err
	}
	c.used[key] = Recording{Prompt: key, Model: answer.Model, Text: answer.Text}
	return llmgw.Completion{Text: restoreCanary(answer.Text, fixedCanary, callerCanary), Model: answer.Model}, nil
}

// Save writes the answers this run used, sorted by prompt.
func (c *Cassette) Save(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	recordings := make([]Recording, 0, len(c.used))
	for _, r := range c.used {
		recordings = append(recordings, r)
	}
	slices.SortFunc(recordings, func(a, b Recording) int {
		switch {
		case a.Prompt < b.Prompt:
			return -1
		case a.Prompt > b.Prompt:
			return 1
		}
		return 0
	})
	return writeJSON(path, recordings)
}

// nonce is the random part of the data markers a pipeline puts around untrusted text and of the
// canary in its system prompt. It differs on each call, so it is not part of the key.
var (
	nonce        = regexp.MustCompile(`(DATA|CANARY)-[0-9a-f]{32}`)
	promptCanary = regexp.MustCompile(`CANARY-([0-9a-f]{32})`)
	outerData    = regexp.MustCompile(`^DATA-([0-9a-f]{32})\n`)
)

// Key names a prompt. The system prompt is part of it, so a new prompt version needs new answers.
func Key(system, user string) string {
	sum := sha256.Sum256([]byte(nonce.ReplaceAllString(system, "${1}-nonce") + "\x00" + nonce.ReplaceAllString(user, "${1}-nonce")))
	return hex.EncodeToString(sum[:])
}

func evalMarker(kind, key string) string {
	sum := sha256.Sum256([]byte("ipso-evals-" + kind + ":" + key))
	return hex.EncodeToString(sum[:16])
}

func normalizeUser(user, key string) string {
	m := outerData.FindStringSubmatch(user)
	if m == nil || !strings.HasSuffix(user, "\nDATA-"+m[1]) {
		return user
	}
	fixed := "DATA-" + evalMarker("data", key)
	markerLen := len("DATA-") + len(m[1])
	return fixed + user[markerLen:len(user)-markerLen] + fixed
}

func restoreCanary(text, fixedCanary, callerCanary string) string {
	if callerCanary == "" || callerCanary == fixedCanary || !strings.Contains(strings.ToLower(text), fixedCanary[:16]) {
		return text
	}
	re := regexp.MustCompile("(?i)" + fixedCanary[:16] + "(?:" + fixedCanary[16:] + ")?")
	return re.ReplaceAllStringFunc(text, func(matched string) string {
		if len(matched) == len(fixedCanary) {
			return callerCanary
		}
		return callerCanary[:16]
	})
}

// Models lists the distinct models that the recorded answers name, sorted.
func (c *Cassette) Models() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := map[string]bool{}
	for _, r := range c.recorded {
		seen[r.Model] = true
	}
	models := make([]string, 0, len(seen))
	for model := range seen {
		models = append(models, model)
	}
	slices.Sort(models)
	return models
}
