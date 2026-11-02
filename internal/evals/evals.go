// Package evals scores the LLM pipelines on golden datasets (ADR-0082). A run replays recorded
// model answers, so it is deterministic and needs no key, and `go test ./...` fails when a score
// drops more than three points below the committed baseline. A live run records fresh answers
// through the LLM gateway. Every dataset is synthetic: no customer text and no real secret.
package evals

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"slices"
	"strings"
	"time"
)

// Tolerance is the largest drop below the baseline that passes: three points on a scale of 100.
const Tolerance = 0.03

// Scores holds each metric of a run, from 0 to 1.
type Scores map[string]float64

// Entry is one metric of the baseline. Min, when set, is a floor that an acceptance criterion
// fixes, and a run below it fails whatever the baseline says.
type Entry struct {
	Score float64  `json:"score"`
	Min   *float64 `json:"min,omitempty"`
}

// Baseline is the committed score of each metric.
type Baseline map[string]Entry

// Gate returns one line for each metric that fails: missing from the run or the baseline, more
// than Tolerance below the baseline, or below its floor. None means the run passes.
func Gate(baseline Baseline, scores Scores) []string {
	var failures []string
	for _, name := range sortedKeys(baseline) {
		entry := baseline[name]
		score, ok := scores[name]
		if !ok {
			failures = append(failures, fmt.Sprintf("%s: the run has no score", name))
			continue
		}
		// Scores are rounded to four places, so an exact three-point drop still passes.
		if round(entry.Score-score) > Tolerance {
			failures = append(failures, fmt.Sprintf("%s: %.4f is more than %.0f points below the baseline %.4f", name, score, Tolerance*100, entry.Score))
		}
		if entry.Min != nil && score < *entry.Min {
			failures = append(failures, fmt.Sprintf("%s: %.4f is below the floor %.4f", name, score, *entry.Min))
		}
	}
	for _, name := range sortedKeys(scores) {
		if _, ok := baseline[name]; !ok {
			failures = append(failures, fmt.Sprintf("%s: not in the baseline; run with -update and review the diff", name))
		}
	}
	return failures
}

// Ratio returns part over whole, rounded, and 0 for an empty whole.
func Ratio(part, whole int) float64 {
	if whole == 0 {
		return 0
	}
	return round(float64(part) / float64(whole))
}

func round(value float64) float64 {
	return math.Round(value*10000) / 10000
}

// LoadBaseline reads the baseline. A missing file is an empty baseline.
func LoadBaseline(path string) (Baseline, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Baseline{}, nil
	}
	if err != nil {
		return nil, err
	}
	var baseline Baseline
	if err := json.Unmarshal(raw, &baseline); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return baseline, nil
}

// Update returns the baseline with this run's scores. A floor stays, and a metric the run did not
// produce is dropped, so a removed suite leaves no stale entry.
func Update(baseline Baseline, scores Scores) Baseline {
	next := Baseline{}
	for name, score := range scores {
		next[name] = Entry{Score: score, Min: baseline[name].Min}
	}
	return next
}

// SaveBaseline writes the baseline with sorted keys, so its diff reads well.
func SaveBaseline(path string, baseline Baseline) error {
	return writeJSON(path, baseline)
}

// AppendHistory adds one line with the date and the scores, so a metric can be followed over time.
func AppendHistory(path string, at time.Time, scores Scores) error {
	line, err := json.Marshal(struct {
		Date   string `json:"date"`
		Scores Scores `json:"scores"`
	}{Date: at.UTC().Format(time.DateOnly), Scores: scores})
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// Table renders the scores as aligned lines for a test log.
func Table(scores Scores) string {
	var b strings.Builder
	for _, name := range sortedKeys(scores) {
		fmt.Fprintf(&b, "%-36s %.4f\n", name, scores[name])
	}
	return b.String()
}

func writeJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(encoded, '\n'), 0o644)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
