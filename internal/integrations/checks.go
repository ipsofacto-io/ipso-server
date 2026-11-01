package integrations

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/ipsofacto-io/ipso/pkg/edrcheck"
)

const (
	checkName          = "ipso / decisions"
	configPath         = ".ipso/config.yaml"
	maxAnnotations     = 50 // the Checks API limit per request
	maxRunAnnotations  = 500
	maxFileProblems    = 10
	maxMessageRunes    = 1000
	maxDecisionFiles   = 200
	maxDecisionBytes   = 1 << 20
	maxChangedFiles    = 3000
	changedFilesPerGet = 100
)

// RepoClient calls the API for one repository with a token scoped to it. repo is owner/name and
// has passed validRepo.
type RepoClient struct {
	app   *App
	token string
	repo  string
}

// Annotation is one line of the Checks API output.
type annotation struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Level     string `json:"annotation_level"`
	Title     string `json:"title"`
	Message   string `json:"message"`
}

type checkOutput struct {
	Title       string       `json:"title"`
	Summary     string       `json:"summary"`
	Annotations []annotation `json:"annotations,omitempty"`
}

type changedFile struct {
	Filename string `json:"filename"`
	Status   string `json:"status"`
}

// outcome is what one run concluded. ipso writes title and summary, so no repository text
// reaches the Markdown of the summary. Repository text reaches only annotation fields, which
// GitHub shows as plain text.
type outcome struct {
	conclusion  string
	title       string
	summary     string
	annotations []annotation
}

func (c *RepoClient) repoPath(suffix string) string {
	return "/repos/" + c.repo + suffix
}

func (c *RepoClient) createCheckRun(ctx context.Context, headSHA string) (int64, error) {
	var run struct {
		ID int64 `json:"id"`
	}
	body := map[string]any{"name": checkName, "head_sha": headSHA, "status": "in_progress"}
	if err := c.app.call(ctx, c.token, http.MethodPost, c.repoPath("/check-runs"), body, &run); err != nil {
		return 0, fmt.Errorf("create the check run: %w", err)
	}
	return run.ID, nil
}

// completeCheckRun sends the annotations in batches, because one request carries at most 50.
// GitHub appends each batch, and the last request closes the run.
func (c *RepoClient) completeCheckRun(ctx context.Context, id int64, result outcome) error {
	path := c.repoPath("/check-runs/" + strconv.FormatInt(id, 10))
	rest := result.annotations
	for {
		batch := rest
		if len(batch) > maxAnnotations {
			batch = rest[:maxAnnotations]
		}
		rest = rest[len(batch):]
		body := map[string]any{"output": checkOutput{Title: result.title, Summary: result.summary, Annotations: batch}}
		if len(rest) == 0 {
			body["status"] = "completed"
			body["conclusion"] = result.conclusion
		}
		if err := c.app.call(ctx, c.token, http.MethodPatch, path, body, nil); err != nil {
			return fmt.Errorf("complete the check run: %w", err)
		}
		if len(rest) == 0 {
			return nil
		}
	}
}

func (c *RepoClient) pullRequestFiles(ctx context.Context, number int) ([]changedFile, error) {
	var files []changedFile
	for page := 1; ; page++ {
		var batch []changedFile
		path := fmt.Sprintf("/pulls/%d/files?per_page=%d&page=%d", number, changedFilesPerGet, page)
		if err := c.app.call(ctx, c.token, http.MethodGet, c.repoPath(path), nil, &batch); err != nil {
			return nil, fmt.Errorf("list the changed files: %w", err)
		}
		files = append(files, batch...)
		if len(files) > maxChangedFiles {
			return nil, errTooManyFiles
		}
		if len(batch) < changedFilesPerGet {
			return files, nil
		}
	}
}

func (c *RepoClient) comparedFiles(ctx context.Context, before, after string) ([]changedFile, error) {
	var files []changedFile
	for page := 1; ; page++ {
		var answer struct {
			Files []changedFile `json:"files"`
		}
		path := fmt.Sprintf("/compare/%s...%s?per_page=%d&page=%d", before, after, changedFilesPerGet, page)
		if err := c.app.call(ctx, c.token, http.MethodGet, c.repoPath(path), nil, &answer); err != nil {
			return nil, fmt.Errorf("compare the commits: %w", err)
		}
		files = append(files, answer.Files...)
		if len(files) > maxChangedFiles {
			return nil, errTooManyFiles
		}
		if len(answer.Files) < changedFilesPerGet {
			return files, nil
		}
	}
}

// fileAt reads one file at one commit. A missing file is ErrNotFound.
func (c *RepoClient) fileAt(ctx context.Context, path, ref string) ([]byte, error) {
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	target := c.repoPath("/contents/" + strings.Join(segments, "/") + "?ref=" + url.QueryEscape(ref))
	return c.app.do(ctx, c.token, http.MethodGet, target, acceptRawFile, nil)
}

var errTooManyFiles = errors.New("too many changed files")

// evaluate validates the decision files among the changed files at ref. An error means the run
// could not finish, and the caller reports that as a failure.
func (c *RepoClient) evaluate(ctx context.Context, ref string, files []changedFile) (outcome, error) {
	globs := edrcheck.DefaultGlobs()
	raw, err := c.fileAt(ctx, configPath, ref)
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return outcome{}, fmt.Errorf("read the config: %w", err)
	default:
		globs, err = edrcheck.ParseGlobs(raw)
		if err != nil {
			return outcome{
				conclusion:  "failure",
				title:       "The ipso config is invalid",
				summary:     "ipso could not read `.ipso/config.yaml`, so it did not check any decision file.",
				annotations: []annotation{failureAt(configPath, err.Error())},
			}, nil
		}
	}

	var decisions []string
	for _, file := range files {
		if file.Status != "removed" && edrcheck.IsDecision(globs, file.Filename) {
			decisions = append(decisions, file.Filename)
		}
	}
	if len(decisions) == 0 {
		return outcome{conclusion: "success", title: "No decision file changed", summary: "This change touches no decision file."}, nil
	}
	if len(decisions) > maxDecisionFiles {
		return outcome{
			conclusion: "failure",
			title:      "Too many decision files",
			summary:    fmt.Sprintf("This change touches %d decision files, and ipso checks at most %d in one run. Run `ipso check` in CI instead.", len(decisions), maxDecisionFiles),
		}, nil
	}

	var annotations []annotation
	invalid := 0
	for _, path := range decisions {
		problems, err := c.problemsIn(ctx, path, ref)
		if err != nil {
			return outcome{}, err
		}
		if len(problems) > 0 {
			invalid++
		}
		for i, problem := range problems {
			if i == maxFileProblems {
				annotations = append(annotations, failureAt(path, fmt.Sprintf("%d more problems. Run ipso check for the full list.", len(problems)-i)))
				break
			}
			annotations = append(annotations, failureAt(path, problem))
		}
	}
	omitted := max(len(annotations)-maxRunAnnotations, 0)
	annotations = annotations[:len(annotations)-omitted]

	if invalid == 0 {
		return outcome{conclusion: "success", title: "Decision files are valid", summary: fmt.Sprintf("ipso checked %d decision files and found no problem.", len(decisions))}, nil
	}
	summary := fmt.Sprintf("%d of %d decision files are invalid. Each problem is annotated on its file.", invalid, len(decisions))
	if omitted > 0 {
		summary += fmt.Sprintf(" %d more problems are not annotated.", omitted)
	}
	return outcome{conclusion: "failure", title: "Decision files are invalid", summary: summary, annotations: annotations}, nil
}

func (c *RepoClient) problemsIn(ctx context.Context, path, ref string) ([]string, error) {
	raw, err := c.fileAt(ctx, path, ref)
	if errors.Is(err, ErrNotFound) {
		return []string{"the file could not be read at this commit"}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read a decision file: %w", err)
	}
	if len(raw) > maxDecisionBytes {
		return []string{"the file is larger than 1 MiB"}, nil
	}
	return edrcheck.Validate(string(raw)), nil
}

func failureAt(path, message string) annotation {
	return annotation{
		Path:      path,
		StartLine: 1,
		EndLine:   1,
		Level:     "failure",
		Title:     "Invalid decision file",
		Message:   plainText(message),
	}
}

// plainText removes control characters and caps the length. The API refuses an empty message.
func plainText(message string) string {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, message)
	runes := []rune(strings.TrimSpace(cleaned))
	if len(runes) > maxMessageRunes {
		runes = runes[:maxMessageRunes]
	}
	if len(runes) == 0 {
		return "the file is invalid"
	}
	return string(runes)
}
