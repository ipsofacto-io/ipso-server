package integrations

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
)

// userLogin is the shape of a GitHub login. It is stricter than ownerLogin: it has no dot, so a login
// is never "." or "..", and it starts with a letter or a digit.
var userLogin = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,38}$`)

// CanWrite reports whether login can write to the repository now. GitHub calculates the answer from
// every grant: the repository, its teams, the organization, and the enterprise, so it holds for an
// organization member who keeps the membership private, which the App's token sees as a contributor
// (ADR-0104). Admin and write count, and GitHub reports the maintain role as write. A text that is not
// a login, an account GitHub does not know, and an account with a lesser role are false. Any other
// failure is an error that names no login.
func (c *RepoClient) CanWrite(ctx context.Context, login string) (bool, error) {
	if !userLogin.MatchString(login) {
		return false, nil
	}
	var answer struct {
		Permission string `json:"permission"`
	}
	path := c.repoPath("/collaborators/" + url.PathEscape(login) + "/permission")
	err := c.app.call(ctx, c.token, http.MethodGet, path, nil, &answer)
	switch {
	case errors.Is(err, ErrNotFound):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("read the permission of an author: %w", err)
	}
	return answer.Permission == "admin" || answer.Permission == "write", nil
}
