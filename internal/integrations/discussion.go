package integrations

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
)

const (
	discussionPerGet = 100
	discussionPages  = 3
)

// Comment is one piece of pull request discussion, as the API returned it. Body is untrusted.
type Comment struct {
	ExternalID  string
	URL         string
	Body        string
	Association string
	AuthorType  string
}

type apiComment struct {
	ID          int64  `json:"id"`
	HTMLURL     string `json:"html_url"`
	Body        string `json:"body"`
	Association string `json:"author_association"`
	User        struct {
		Type string `json:"type"`
	} `json:"user"`
}

// Discussion reads the pull request body, its conversation comments, its review summaries, and
// its review comments, up to 300 of each, oldest first. Reading stops at that bound rather than
// failing, so a very long thread still yields proposals from its start.
func (c *RepoClient) Discussion(ctx context.Context, number int) ([]Comment, error) {
	var pull apiComment
	if err := c.app.call(ctx, c.token, http.MethodGet, c.repoPath(fmt.Sprintf("/pulls/%d", number)), nil, &pull); err != nil {
		return nil, fmt.Errorf("read the pull request: %w", err)
	}
	comments := []Comment{{
		ExternalID:  "pull-" + strconv.Itoa(number),
		URL:         pull.HTMLURL,
		Body:        pull.Body,
		Association: pull.Association,
		AuthorType:  pull.User.Type,
	}}
	for _, source := range []struct{ prefix, path string }{
		{"issuecomment-", fmt.Sprintf("/issues/%d/comments", number)},
		{"pullrequestreview-", fmt.Sprintf("/pulls/%d/reviews", number)},
		{"discussion-", fmt.Sprintf("/pulls/%d/comments", number)},
	} {
		for page := 1; page <= discussionPages; page++ {
			var batch []apiComment
			path := fmt.Sprintf("%s?per_page=%d&page=%d", source.path, discussionPerGet, page)
			if err := c.app.call(ctx, c.token, http.MethodGet, c.repoPath(path), nil, &batch); err != nil {
				return nil, fmt.Errorf("read the discussion: %w", err)
			}
			for _, item := range batch {
				comments = append(comments, Comment{
					ExternalID:  source.prefix + strconv.FormatInt(item.ID, 10),
					URL:         item.HTMLURL,
					Body:        item.Body,
					Association: item.Association,
					AuthorType:  item.User.Type,
				})
			}
			if len(batch) < discussionPerGet {
				break
			}
		}
	}
	return comments, nil
}
