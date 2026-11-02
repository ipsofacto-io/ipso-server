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
	"sync"

	"github.com/ipsofacto-io/ipso-server/internal/llmgw"
)

// CompleteFunc is the shape every pipeline takes for the LLM.
type CompleteFunc func(ctx context.Context, system, user string) (llmgw.Completion, error)

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
	live     CompleteFunc
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
func (c *Cassette) Record(live CompleteFunc) {
	c.live = live
}

// Complete answers one prompt.
func (c *Cassette) Complete(ctx context.Context, system, user string) (llmgw.Completion, error) {
	key := Key(system, user)
	c.mu.Lock()
	defer c.mu.Unlock()
	if r, ok := c.used[key]; ok {
		return llmgw.Completion{Text: r.Text, Model: r.Model}, nil
	}
	if c.live == nil {
		r, ok := c.recorded[key]
		if !ok {
			return llmgw.Completion{}, fmt.Errorf("%w (key %s)", ErrNotRecorded, key[:12])
		}
		c.used[key] = r
		return llmgw.Completion{Text: r.Text, Model: r.Model}, nil
	}
	answer, err := c.live(ctx, system, user)
	if err != nil {
		return llmgw.Completion{}, err
	}
	c.used[key] = Recording{Prompt: key, Model: answer.Model, Text: answer.Text}
	return answer, nil
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

// nonce is the random part of the data markers a pipeline puts around untrusted text. It differs
// on each call, so it is not part of the key.
var nonce = regexp.MustCompile(`DATA-[0-9a-f]{32}`)

// Key names a prompt. The system prompt is part of it, so a new prompt version needs new answers.
func Key(system, user string) string {
	sum := sha256.Sum256([]byte(system + "\x00" + nonce.ReplaceAllString(user, "DATA-nonce")))
	return hex.EncodeToString(sum[:])
}
