package integrations

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

const (
	// patchesPerGet is smaller than changedFilesPerGet, because a page of patches holds diff text.
	patchesPerGet = 30
	// MaxPatchFiles is the most changed files the advisory job of a pull request reads (ADR-0173).
	MaxPatchFiles = 500
)

// PullRequest is what the advisory job reads of a pull request before it sends anything to a model
// (ADR-0173). Author and AuthorType are untrusted until RepoClient.CanWrite says the login can write to
// the repository. HeadRepositoryID is 0 when the head repository is gone, as for a deleted fork.
type PullRequest struct {
	Number           int
	State            string
	Draft            bool
	HeadSHA          string
	BaseSHA          string
	HeadRepositoryID int64
	BaseRepositoryID int64
	Author           string
	AuthorType       string
	ChangedFiles     int
}

type apiPullRequest struct {
	Number       int    `json:"number"`
	State        string `json:"state"`
	Draft        bool   `json:"draft"`
	ChangedFiles int    `json:"changed_files"`
	User         struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"user"`
	Head apiBranch `json:"head"`
	Base apiBranch `json:"base"`
}

type apiBranch struct {
	SHA  string `json:"sha"`
	Repo *struct {
		ID int64 `json:"id"`
	} `json:"repo"`
}

func (b apiBranch) repositoryID() int64 {
	if b.Repo == nil {
		return 0
	}
	return b.Repo.ID
}

// PullRequest reads the pull request as it is now. An answer for another number, or with a head or a base
// that is not a commit SHA, is an error, so a caller never pins the wrong commits.
func (c *RepoClient) PullRequest(ctx context.Context, number int) (PullRequest, error) {
	var pull apiPullRequest
	if err := c.app.call(ctx, c.token, http.MethodGet, c.repoPath(fmt.Sprintf("/pulls/%d", number)), nil, &pull); err != nil {
		return PullRequest{}, fmt.Errorf("read the pull request: %w", err)
	}
	if pull.Number != number || !validSHA.MatchString(pull.Head.SHA) || !validSHA.MatchString(pull.Base.SHA) || pull.ChangedFiles < 0 {
		return PullRequest{}, errors.New("read the pull request: the answer is not the pull request asked for")
	}
	return PullRequest{
		Number:           pull.Number,
		State:            pull.State,
		Draft:            pull.Draft,
		HeadSHA:          pull.Head.SHA,
		BaseSHA:          pull.Base.SHA,
		HeadRepositoryID: pull.Head.repositoryID(),
		BaseRepositoryID: pull.Base.repositoryID(),
		Author:           pull.User.Login,
		AuthorType:       pull.User.Type,
		ChangedFiles:     pull.ChangedFiles,
	}, nil
}

// Patch is one changed file of a pull request and the unified diff GitHub keeps for it. Patch is empty
// when GitHub sends none: for a binary file, a change with no text hunk, or a diff it will not render.
// Changes counts the added and removed lines, so a file with no patch and no changes, such as a pure
// rename, is told apart from one whose diff is missing. Every field is untrusted repository content.
type Patch struct {
	Filename         string `json:"filename"`
	PreviousFilename string `json:"previous_filename"`
	Status           string `json:"status"`
	Changes          int    `json:"changes"`
	Patch            string `json:"patch"`
}

// PullRequestPatches lists the changed files of a pull request with their patches, in pages of 30. GitHub
// lists the head the pull request has now, so a caller that pinned a head reads the pull request again
// afterwards. More than MaxPatchFiles files is ErrTooManyFiles, and a page longer than asked for, a file
// with no name or a negative count is an error.
func (c *RepoClient) PullRequestPatches(ctx context.Context, number int) ([]Patch, error) {
	var files []Patch
	for page := 1; ; page++ {
		var batch []Patch
		path := fmt.Sprintf("/pulls/%d/files?per_page=%d&page=%d", number, patchesPerGet, page)
		if err := c.app.call(ctx, c.token, http.MethodGet, c.repoPath(path), nil, &batch); err != nil {
			return nil, fmt.Errorf("list the patches: %w", err)
		}
		if len(batch) > patchesPerGet {
			return nil, errors.New("list the patches: the page is longer than asked for")
		}
		for _, file := range batch {
			if file.Filename == "" || file.Changes < 0 {
				return nil, errors.New("list the patches: a file has no name or a negative count")
			}
		}
		files = append(files, batch...)
		if len(files) > MaxPatchFiles {
			return nil, ErrTooManyFiles
		}
		if len(batch) < patchesPerGet {
			return files, nil
		}
	}
}
