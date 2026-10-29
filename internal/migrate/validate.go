package migrate

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// fileName is the one accepted name: a five digit version, a lowercase slug, and .sql.
var fileName = regexp.MustCompile(`^([0-9]{5})_[a-z0-9_]+\.sql$`)

// allowedAnnotations are the goose annotations a file may use. Down, ENVSUB ON, and
// ENVSUB OFF are absent on purpose: ADR-0050 allows a forward fix only, and the reviewed
// bytes must be the applied bytes.
var allowedAnnotations = map[string]bool{
	"Up":             true,
	"StatementBegin": true,
	"StatementEnd":   true,
	"NO TRANSACTION": true,
}

// gooseAnnotations is the full set goose v3.29.0 understands.
var gooseAnnotations = []string{
	"Up", "Down", "StatementBegin", "StatementEnd", "NO TRANSACTION", "ENVSUB ON", "ENVSUB OFF",
}

// Validate checks the migration files in fsys against the file rules of ADR-0050.
// It reads files only and opens no connection.
func Validate(fsys fs.FS) error {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	if len(entries) == 0 {
		return errors.New("no migrations")
	}
	var errs []error
	seen := make(map[int]string, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() {
			errs = append(errs, fmt.Errorf("%s: not a regular file", name))
			continue
		}
		match := fileName.FindStringSubmatch(name)
		if match == nil {
			errs = append(errs, fmt.Errorf("%s: not a migration file name (want NNNNN_slug.sql)", name))
			continue
		}
		version, _ := strconv.Atoi(match[1])
		if other, ok := seen[version]; ok {
			errs = append(errs, fmt.Errorf("%s: duplicate version %d, also used by %s", name, version, other))
			continue
		}
		seen[version] = name
		if err := validateFile(fsys, name); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	errs = append(errs, checkSequence(seen)...)
	return errors.Join(errs...)
}

// checkSequence requires the versions to run 1..n with no gap.
func checkSequence(seen map[int]string) []error {
	versions := make([]int, 0, len(seen))
	for v := range seen {
		versions = append(versions, v)
	}
	sort.Ints(versions)
	var errs []error
	for i, v := range versions {
		if want := i + 1; v != want {
			errs = append(errs, fmt.Errorf("%s: version %d breaks the sequence, want %d", seen[v], v, want))
			break
		}
	}
	return errs
}

func validateFile(fsys fs.FS, name string) error {
	file, err := fsys.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	var errs []error
	up := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for line := 1; scanner.Scan(); line++ {
		text := scanner.Text()
		// goose reads an annotation from any line that starts with "--" and holds "+goose",
		// including a line inside a function body. Match that rule exactly.
		if !strings.HasPrefix(strings.TrimSpace(text), "--") || !strings.Contains(text, "+goose") {
			continue
		}
		annotation, err := parseAnnotation(text)
		if err != nil {
			errs = append(errs, fmt.Errorf("line %d: %w", line, err))
			continue
		}
		if !allowedAnnotations[annotation] {
			errs = append(errs, fmt.Errorf("line %d: annotation %q is not allowed", line, annotation))
			continue
		}
		if annotation == "Up" {
			up++
		}
	}
	if err := scanner.Err(); err != nil {
		errs = append(errs, err)
	}
	if up != 1 {
		errs = append(errs, fmt.Errorf("want exactly one '-- +goose Up', found %d", up))
	}
	return errors.Join(errs...)
}

// parseAnnotation normalizes a "-- +goose <annotation>" line the way goose v3.29.0 does:
// leading whitespace is an error, every "--" and the first "+goose" are removed, a second
// "+goose" is an error, and the rest matches a known annotation without regard to case.
func parseAnnotation(line string) (string, error) {
	if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
		return "", errors.New("goose annotation has leading whitespace")
	}
	command := strings.ReplaceAll(line, "--", "")
	command = strings.Replace(command, "+goose", "", 1)
	if strings.Contains(command, "+goose") {
		return "", errors.New("line holds more than one '+goose'")
	}
	command = strings.TrimSpace(command)
	for _, known := range gooseAnnotations {
		if strings.EqualFold(known, command) {
			return known, nil
		}
	}
	return "", fmt.Errorf("unknown goose annotation %q", command)
}
