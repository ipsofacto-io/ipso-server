package api

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
)

// bounded gives every request a deadline and holds every answer until it is complete. An answer
// over the cap is refused whole with 500 and never sent cut short, so an audit answer cannot be
// mistaken for a complete one (ADR-0055). A request past its deadline is 503.
func bounded(next http.Handler, limits Limits, log *slog.Logger) http.Handler {
	capped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		answer := &cappedWriter{header: http.Header{}, max: limits.ResponseBytes}
		next.ServeHTTP(answer, r)
		if answer.over {
			log.Warn("an answer was over the response cap and was refused", "path", r.URL.Path, "cap", limits.ResponseBytes)
			writeError(w, http.StatusInternalServerError, errResponseTooLarge)
			return
		}
		for key, values := range answer.header {
			w.Header()[key] = values
		}
		if answer.status == 0 {
			answer.status = http.StatusOK
		}
		w.WriteHeader(answer.status)
		// The buffer is the JSON answer already encoded, with Content-Type application/json.
		_, _ = io.Copy(w, bytes.NewReader(answer.body.Bytes()))
	})
	timed := http.TimeoutHandler(capped, limits.Timeout, errorJSON(errTimeout))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TimeoutHandler writes its own answer on a timeout and copies the route's headers otherwise,
		// so these are the timeout answer's headers.
		setJSONHeaders(w.Header())
		timed.ServeHTTP(w, r)
	})
}

var errOverCap = errors.New("the answer is over the response cap")

// cappedWriter keeps an answer of up to max bytes and drops the rest.
type cappedWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
	max    int
	over   bool
}

func (c *cappedWriter) Header() http.Header { return c.header }

func (c *cappedWriter) WriteHeader(status int) {
	if c.status == 0 {
		c.status = status
	}
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if c.over || c.body.Len()+len(p) > c.max {
		c.over = true
		return 0, errOverCap
	}
	return c.body.Write(p)
}
