package proposals

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/integrations"
	"github.com/ipsofacto-io/ipso-server/internal/llmgw"
	"github.com/ipsofacto-io/ipso-server/internal/registry"
	"github.com/ipsofacto-io/ipso-server/internal/verification"
)

// MaxAdvisoryChecks is the most llm-advisory checks one head commit of a pull request evaluates, in decision
// id order and then check index order, so the same checks are taken on every head (ADR-0174).
const MaxAdvisoryChecks = 10

// The reasons a whole pull request is skipped. Each is a constant, so the log of a job holds no text of its own.
const (
	SkipClosed       = "closed"
	SkipStale        = "stale"
	SkipDraft        = "draft"
	SkipFork         = "fork"
	SkipBase         = "base"
	SkipUntrusted    = "untrusted"
	SkipTooManyFiles = "too_many_files"
)

// PullRequestReader is what the advisory job reads from GitHub with the token the webhooks service limited to
// one repository: integrations.RepoClient.
type PullRequestReader interface {
	PullRequest(ctx context.Context, number int) (integrations.PullRequest, error)
	PullRequestPatches(ctx context.Context, number int) ([]integrations.Patch, error)
	FileAt(ctx context.Context, path, ref string) ([]byte, error)
	CanWrite(ctx context.Context, login string) (bool, error)
}

// AdvisoryStats counts what one advisory job did. It holds no text, no path and no person (ADR-0012).
type AdvisoryStats struct {
	// Skipped says why the whole pull request was skipped, or is empty.
	Skipped string
	// Checks counts the llm-advisory checks in scope, and Capped those past MaxAdvisoryChecks.
	Checks int
	Capped int
	// Known counts the checks that already had a verdict for this head, and Reused those whose answer on an
	// earlier head was copied because they sent the same input.
	Known  int
	Reused int
	Stored int
	// Refused counts the answers that were not one advisory verdict.
	Refused int
	// Unsendable counts the checks skipped before a call: a file ipso never sends, a file with no patch, a
	// patch that does not match its counts, too many hunks, or too much text.
	Unsendable int
	// NoPrompt counts the checks whose prompt file is not a valid ref, is missing at the base commit, or is too long.
	NoPrompt int
	// Empty counts the checks whose files hold no text change.
	Empty int
	// Flagged counts the hunks the injection screen flagged. They are sent all the same.
	Flagged int
}

// OnPullRequest returns the hook the webhooks service runs for an open pull request of a repository the tenant
// opted in to llm-advisory checks (ADR-0174). It runs RunAdvisory through the gateway for the tenant the
// installation mapping gave, with the client the service limited to that repository. The log holds counts and
// the repository id, never a path, a diff, an answer or a person (ADR-0012).
func OnPullRequest(db *sql.DB, gateway *llmgw.Gateway, log *slog.Logger) func(context.Context, integrations.OpenPullRequest) error {
	return func(ctx context.Context, pr integrations.OpenPullRequest) error {
		if pr.Tenant == uuid.Nil {
			return errors.New("no tenant")
		}
		if pr.Client == nil {
			return errors.New("no client")
		}
		stats, err := RunAdvisory(ctx, db, SchemaCompleteFunc(gateway.ForSchema(pr.Tenant)), pr.Client, pr)
		if err != nil {
			return err
		}
		log.InfoContext(ctx, "pull request advisory checks processed", "tenant", pr.Tenant.String(), "repository_id", pr.RepositoryID, "pull_request", pr.Number,
			"skipped", stats.Skipped, "checks", stats.Checks, "capped", stats.Capped, "known", stats.Known, "reused", stats.Reused,
			"stored", stats.Stored, "refused", stats.Refused, "unsendable", stats.Unsendable, "no_prompt", stats.NoPrompt,
			"empty", stats.Empty, "flagged", stats.Flagged)
		return nil
	}
}

// RunAdvisory evaluates the llm-advisory checks of the decisions in force for the files of one open pull
// request, and stores one advisory verdict for each check it could send. The tenant of pr must be the one the
// installation mapping gave, because RunAdvisory trusts it. pr.Client is not used: gh reads GitHub.
//
// Nothing is sent unless every gate holds, in this order: the pull request is open, its head is still the one
// the delivery named, it is not a draft, its head branch is in the repository itself and not a fork, it targets
// the default branch, whose base commit holds the check prompt, and its author is a person who can write to the
// repository now (ADR-0104). A pull request of more files than integrations.MaxPatchFiles is skipped. A GitHub
// error fails the job, so a redelivery can retry it.
//
// For each check, the hunks of the files in its scope are sent with the decision text and the prompt file its
// ref names, read at the base commit so that the change cannot rewrite what judges it. A check that already has
// a verdict for this head is not sent again, and one that sends the same input as on an earlier head reuses that
// answer. No transaction is open while the model answers.
func RunAdvisory(ctx context.Context, db *sql.DB, complete SchemaCompleteFunc, gh PullRequestReader, pr integrations.OpenPullRequest) (AdvisoryStats, error) {
	var stats AdvisoryStats
	if pr.Tenant == uuid.Nil || db == nil || complete == nil || gh == nil {
		return stats, errors.New("advisory: a tenant, a database, a model and GitHub are required")
	}
	pull, err := gh.PullRequest(ctx, pr.Number)
	if err != nil {
		return stats, err
	}
	if stats.Skipped = pullRequestGate(pull, pr); stats.Skipped != "" {
		return stats, nil
	}
	if pull.AuthorType != "User" {
		stats.Skipped = SkipUntrusted
		return stats, nil
	}
	allowed, err := gh.CanWrite(ctx, pull.Author)
	if err != nil {
		return stats, err
	}
	if !allowed {
		stats.Skipped = SkipUntrusted
		return stats, nil
	}
	if pull.ChangedFiles > integrations.MaxPatchFiles {
		stats.Skipped = SkipTooManyFiles
		return stats, nil
	}
	patches, err := gh.PullRequestPatches(ctx, pr.Number)
	if errors.Is(err, integrations.ErrTooManyFiles) {
		stats.Skipped = SkipTooManyFiles
		return stats, nil
	}
	if err != nil {
		return stats, err
	}
	// GitHub lists the files of the head the pull request has now, so the head is read again.
	again, err := gh.PullRequest(ctx, pr.Number)
	if err != nil {
		return stats, err
	}
	if again.HeadSHA != pr.HeadSHA {
		stats.Skipped = SkipStale
		return stats, nil
	}

	paths, files := scopePaths(patches)
	if len(paths) == 0 {
		return stats, nil
	}
	repo := strings.ToLower(pr.Repo)
	resolved, err := resolveAll(ctx, db, pr.Tenant, repo, paths, time.Now())
	if err != nil {
		return stats, err
	}
	inScope := map[uuid.UUID][]int{}
	for _, resolution := range resolved.Resolutions {
		for _, id := range resolution.DecisionIDs {
			for _, file := range files[resolution.Path] {
				if !slices.Contains(inScope[id], file) {
					inScope[id] = append(inScope[id], file)
				}
			}
		}
	}

	checks := advisoryChecks(resolved.Decisions)
	stats.Checks = len(checks)
	if len(checks) > MaxAdvisoryChecks {
		stats.Capped = len(checks) - MaxAdvisoryChecks
		checks = checks[:MaxAdvisoryChecks]
	}
	prompts := map[string]promptFile{}
	for _, check := range checks {
		target := verification.AdvisoryCheck{
			RepositoryID: pr.RepositoryID, PullNumber: pr.Number, HeadSHA: pr.HeadSHA,
			DecisionID: check.decision.ID, DecisionVersion: check.decision.Version, CheckIndex: check.index,
		}
		known, err := verification.HasAdvisory(ctx, db, pr.Tenant, target)
		if err != nil {
			return stats, err
		}
		if known {
			stats.Known++
			continue
		}
		slices.Sort(inScope[check.decision.ID])
		hunks, sendable := hunksOf(patches, inScope[check.decision.ID])
		switch {
		case !sendable:
			stats.Unsendable++
			continue
		case len(hunks) == 0:
			stats.Empty++
			continue
		}
		prompt, found, err := readCheckPrompt(ctx, gh, prompts, check.ref, pull.BaseSHA)
		if err != nil {
			return stats, err
		}
		if !found {
			stats.NoPrompt++
			continue
		}
		prepared, err := PrepareAdvisory(AdvisoryRequest{Title: check.decision.Title, Statement: check.decision.Statement, CheckPrompt: prompt.text, Hunks: hunks})
		if err != nil {
			stats.Unsendable++
			continue
		}
		stats.Flagged += prepared.Flagged()
		reused, err := verification.ReuseAdvisory(ctx, db, pr.Tenant, target, pull.BaseSHA, AdvisoryPromptVersion, prepared.Input, prompt.digest)
		if err != nil {
			return stats, err
		}
		if reused {
			stats.Reused++
			continue
		}
		answer, err := Advise(ctx, complete, prepared)
		switch {
		case errors.Is(err, ErrAdvisoryAnswer):
			stats.Refused++
			continue
		case err != nil:
			return stats, err
		}
		created, err := verification.StoreAdvisory(ctx, db, pr.Tenant, verification.AdvisoryVerdict{
			AdvisoryCheck: target,
			Repo:          repo,
			BaseSHA:       pull.BaseSHA,
			Assessment:    answer.Assessment,
			Cited:         answer.Cited,
			Reason:        answer.Reason,
			ModelID:       answer.Model,
			PromptVersion: answer.PromptVersion,
			InputSHA256:   prepared.Input,
			PromptSHA256:  prompt.digest,
		})
		switch {
		case errors.Is(err, verification.ErrInvalidAdvisory):
			stats.Refused++
		case err != nil:
			return stats, err
		case created:
			stats.Stored++
		default:
			stats.Known++
		}
	}
	return stats, nil
}

// pullRequestGate is the first reason to skip the pull request, or empty when it passes.
func pullRequestGate(pull integrations.PullRequest, pr integrations.OpenPullRequest) string {
	switch {
	case pull.State != "open":
		return SkipClosed
	case pull.HeadSHA != pr.HeadSHA:
		return SkipStale
	case pull.Draft:
		return SkipDraft
	case pull.HeadRepositoryID == 0 || pull.HeadRepositoryID != pull.BaseRepositoryID || pull.BaseRepositoryID != pr.RepositoryID:
		// Every commit on a branch of the repository itself was pushed by someone who can write to it.
		return SkipFork
	case pull.DefaultBranch == "" || pull.BaseRef != pull.DefaultBranch:
		// The check prompt is read at the base commit. Into another branch, the author would choose that
		// commit, and with it the prompt that judges the change.
		return SkipBase
	}
	return ""
}

// scopePaths returns each name of a changed file, new and previous, that the registry accepts, once, and for
// each name the files that carry it.
func scopePaths(patches []integrations.Patch) ([]string, map[string][]int) {
	var paths []string
	files := map[string][]int{}
	for i, patch := range patches {
		for _, name := range []string{patch.Filename, patch.PreviousFilename} {
			if !registry.ValidPath(name) || slices.Contains(files[name], i) {
				continue
			}
			if _, seen := files[name]; !seen {
				paths = append(paths, name)
			}
			files[name] = append(files[name], i)
		}
	}
	return paths, files
}

// resolveAll resolves paths in batches the registry accepts, all at the same time, so a pull request of at
// most MaxPatchFiles files is resolved whole even when each file is a rename and carries two names. A decision
// in force for paths of two batches is kept once.
func resolveAll(ctx context.Context, db *sql.DB, tenant uuid.UUID, repo string, paths []string, now time.Time) (registry.Resolved, error) {
	var all registry.Resolved
	kept := map[uuid.UUID]bool{}
	for batch := range slices.Chunk(paths, registry.MaxResolvePaths) {
		resolved, err := registry.ResolvePathsAnyEnv(ctx, db, tenant, repo, batch, now, now)
		if err != nil {
			return registry.Resolved{}, err
		}
		all.Resolutions = append(all.Resolutions, resolved.Resolutions...)
		for _, decision := range resolved.Decisions {
			if !kept[decision.ID] {
				kept[decision.ID] = true
				all.Decisions = append(all.Decisions, decision)
			}
		}
	}
	return all, nil
}

// hunksOf parses the patches of the files in a check's scope, in the order GitHub listed them. A file ipso
// never sends, a file whose diff GitHub left out though lines changed, and a patch that does not match its
// counts make the check unsendable, so a check never judges part of a change as if it were the whole. More
// than MaxAdvisoryHunks hunks does too.
func hunksOf(patches []integrations.Patch, files []int) ([]Hunk, bool) {
	var hunks []Hunk
	for _, i := range files {
		patch := patches[i]
		if NeverSent(patch.Filename) || (patch.PreviousFilename != "" && NeverSent(patch.PreviousFilename)) {
			return nil, false
		}
		if patch.Patch == "" {
			if patch.Changes > 0 {
				return nil, false
			}
			continue
		}
		parsed, err := ParsePatch(patch.Filename, patch.Patch)
		if err != nil {
			return nil, false
		}
		hunks = append(hunks, parsed...)
		if len(hunks) > MaxAdvisoryHunks {
			return nil, false
		}
	}
	return hunks, true
}

// advisoryCheck is one llm-advisory check of a decision in force that judges a diff.
type advisoryCheck struct {
	decision DecisionInForce
	index    int
	ref      string
}

// advisoryChecks returns the llm-advisory checks whose target is absent or diff, of each decision that
// InForce keeps, so a sensitive decision is never sent, in decision id order and then index order. The mode a
// check declares is not read: an llm-advisory verdict is always advisory (ADR-0005, ADR-0158).
func advisoryChecks(decisions []registry.Decision) []advisoryCheck {
	kept := map[uuid.UUID]DecisionInForce{}
	for _, decision := range InForce(decisions) {
		kept[decision.ID] = decision
	}
	ordered := slices.Clone(decisions)
	slices.SortFunc(ordered, func(a, b registry.Decision) int { return bytes.Compare(a.ID[:], b.ID[:]) })
	var out []advisoryCheck
	for _, decision := range ordered {
		shown, ok := kept[decision.ID]
		if !ok {
			continue
		}
		var body struct {
			Checks []struct {
				Engine string `json:"engine"`
				Target string `json:"target"`
				Ref    string `json:"ref"`
			} `json:"checks"`
		}
		if json.Unmarshal(decision.Body, &body) != nil {
			continue
		}
		for index, check := range body.Checks {
			if check.Engine == "llm-advisory" && (check.Target == "" || check.Target == "diff") {
				out = append(out, advisoryCheck{decision: shown, index: index, ref: check.Ref})
			}
		}
	}
	return out
}

// promptFile is the prompt file a check names: its text and the SHA-256 of its bytes, or nothing when the
// check names no ref.
type promptFile struct {
	text   string
	digest []byte
	found  bool
}

// readCheckPrompt reads the prompt file of a check at the base commit, once per ref for one job. A ref that is
// not valid or names a file NeverSent keeps from a model, a file missing at that commit, and a file that is not
// text of at most MaxCheckPromptRunes are not found, and a ref NeverSent refuses is never read. A check with no
// ref needs no file.
func readCheckPrompt(ctx context.Context, gh PullRequestReader, cache map[string]promptFile, ref, base string) (promptFile, bool, error) {
	if ref == "" {
		return promptFile{found: true}, true, nil
	}
	if cached, ok := cache[ref]; ok {
		return cached, cached.found, nil
	}
	var prompt promptFile
	if ValidCheckPromptRef(ref) && !NeverSent(ref) {
		raw, err := gh.FileAt(ctx, ref, base)
		switch {
		case errors.Is(err, integrations.ErrNotFound):
		case err != nil:
			return promptFile{}, false, err
		case len(raw) <= 4*MaxCheckPromptRunes && utf8.Valid(raw) && utf8.RuneCount(raw) <= MaxCheckPromptRunes:
			digest := sha256.Sum256(raw)
			prompt = promptFile{text: string(raw), digest: digest[:], found: true}
		}
	}
	cache[ref] = prompt
	return prompt, prompt.found, nil
}
