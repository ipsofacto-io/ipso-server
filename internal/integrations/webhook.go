package integrations

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	webhookPath    = "/webhooks/github"
	maxWebhookBody = 5 << 20
	queueSize      = 256
	workerCount    = 4
	jobTimeout     = 2 * time.Minute
	// evaluateTimeout leaves the rest of jobTimeout to close the check run.
	evaluateTimeout = 100 * time.Second
	seenDeliveries  = 4096
	drainTimeout    = 30 * time.Second
	zeroSHA         = "0000000000000000000000000000000000000000"
)

var (
	validRepo = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]*/[A-Za-z0-9_-][A-Za-z0-9_.-]*$`)
	validSHA  = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	// validDelivery bounds what a signed header can put in the log and the seen set.
	validDelivery = regexp.MustCompile(`^[0-9A-Za-z-]{1,64}$`)
)

// MergedPullRequest is a merged pull request and a client limited to reading its discussion.
type MergedPullRequest struct {
	InstallationID int64
	Repo           string
	Number         int
	Client         *RepoClient
}

// Config is what the service needs. OnMerged is optional. When it is nil, a merged pull request
// mints no token and starts no work (ADR-0062).
type Config struct {
	App           *App
	WebhookSecret []byte
	Logger        *slog.Logger
	OnMerged      func(context.Context, MergedPullRequest) error
}

// Service verifies webhooks and runs their jobs on a bounded queue.
type Service struct {
	cfg   Config
	queue chan job
	seen  *deliverySet
}

type job struct {
	delivery string
	name     string
	run      func(context.Context) error
}

// NewService returns a service. Run its workers with Run before serving Handler.
func NewService(cfg Config) *Service {
	return &Service{cfg: cfg, queue: make(chan job, queueSize), seen: newDeliverySet(seenDeliveries)}
}

// Run works the queue until ctx ends, then finishes what was queued, for at most drainTimeout.
func (s *Service) Run(ctx context.Context) {
	jobContext, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	var workers sync.WaitGroup
	stop := make(chan struct{})
	for range workerCount {
		workers.Go(func() {
			for {
				select {
				case next := <-s.queue:
					s.work(jobContext, next)
				case <-stop:
					for {
						select {
						case next := <-s.queue:
							s.work(jobContext, next)
						default:
							return
						}
					}
				}
			}
		})
	}
	<-ctx.Done()
	close(stop)
	done := make(chan struct{})
	go func() {
		workers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(drainTimeout):
		cancel()
		<-done
	}
}

// work runs one job. A failed job forgets its delivery, so that a redelivery from GitHub can
// retry it. A panic on hostile input fails that job and leaves the process running.
func (s *Service) work(ctx context.Context, next job) {
	ctx, cancel := context.WithTimeout(ctx, jobTimeout)
	defer cancel()
	err := func() (err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = errors.New("the job panicked")
			}
		}()
		return next.run(ctx)
	}()
	if err != nil {
		s.seen.forget(next.delivery)
		s.cfg.Logger.Error("webhook job failed", "delivery", next.delivery, "job", next.name, "error", err)
		return
	}
	s.cfg.Logger.Info("webhook job finished", "delivery", next.delivery, "job", next.name)
}

// Handler serves POST /webhooks/github. The signature is checked over the raw bytes before any
// parsing. The handler answers before the job runs, because GitHub gives a delivery 10 seconds.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+webhookPath, s.receive)
	return mux
}

func (s *Service) receive(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !validSignature(s.cfg.WebhookSecret, body, r.Header.Get("X-Hub-Signature-256")) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	delivery := r.Header.Get("X-GitHub-Delivery")
	if !validDelivery.MatchString(delivery) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	next, err := s.route(r.Header.Get("X-GitHub-Event"), body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if next == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	next.delivery = delivery
	if !s.seen.add(delivery) {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	select {
	case s.queue <- *next:
		w.WriteHeader(http.StatusAccepted)
	default:
		// GitHub records the failed delivery, and it can be redelivered.
		s.seen.forget(delivery)
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}
}

func validSignature(secret, body []byte, header string) bool {
	digest, found := strings.CutPrefix(header, "sha256=")
	if !found || len(secret) == 0 {
		return false
	}
	given, err := hex.DecodeString(digest)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(given, mac.Sum(nil))
}

type repository struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
}

type installation struct {
	ID int64 `json:"id"`
}

// route turns a signed event into a job. nil means the event needs no work. An error means a
// handled event is malformed.
func (s *Service) route(event string, body []byte) (*job, error) {
	switch event {
	case "pull_request":
		return s.routePullRequest(body)
	case "push":
		return s.routePush(body)
	default:
		return nil, nil
	}
}

func (s *Service) routePullRequest(body []byte) (*job, error) {
	var payload struct {
		Action       string       `json:"action"`
		Number       int          `json:"number"`
		Installation installation `json:"installation"`
		Repository   repository   `json:"repository"`
		PullRequest  struct {
			Merged bool `json:"merged"`
			Head   struct {
				SHA string `json:"sha"`
			} `json:"head"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, errors.New("not JSON")
	}
	switch payload.Action {
	case "opened", "synchronize", "reopened":
		if err := validTarget(payload.Installation, payload.Repository); err != nil {
			return nil, err
		}
		if !validSHA.MatchString(payload.PullRequest.Head.SHA) || payload.Number <= 0 {
			return nil, errors.New("bad pull request")
		}
		number, sha := payload.Number, payload.PullRequest.Head.SHA
		return s.checkJob("pull_request", payload.Installation, payload.Repository, sha, map[string]string{
			"checks": writeAccess, "contents": readAccess, "metadata": readAccess, "pull_requests": readAccess,
		}, func(ctx context.Context, c *RepoClient) ([]changedFile, error) {
			return c.pullRequestFiles(ctx, number)
		}), nil
	case "closed":
		if !payload.PullRequest.Merged || s.cfg.OnMerged == nil {
			return nil, nil
		}
		if err := validTarget(payload.Installation, payload.Repository); err != nil {
			return nil, err
		}
		if payload.Number <= 0 {
			return nil, errors.New("bad pull request")
		}
		return &job{name: "merged", run: func(ctx context.Context) error {
			client, err := s.cfg.App.repoClient(ctx, payload.Installation.ID, payload.Repository.ID, payload.Repository.FullName, map[string]string{
				"metadata": readAccess, "pull_requests": readAccess,
			})
			if err != nil {
				return err
			}
			return s.cfg.OnMerged(ctx, MergedPullRequest{
				InstallationID: payload.Installation.ID,
				Repo:           payload.Repository.FullName,
				Number:         payload.Number,
				Client:         client,
			})
		}}, nil
	default:
		return nil, nil
	}
}

func (s *Service) routePush(body []byte) (*job, error) {
	var payload struct {
		Ref          string       `json:"ref"`
		Before       string       `json:"before"`
		After        string       `json:"after"`
		Deleted      bool         `json:"deleted"`
		Installation installation `json:"installation"`
		Repository   repository   `json:"repository"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, errors.New("not JSON")
	}
	// A branch with a pull request is already checked there, and a tag changes nothing.
	if payload.Deleted || payload.Ref != "refs/heads/"+payload.Repository.DefaultBranch {
		return nil, nil
	}
	if err := validTarget(payload.Installation, payload.Repository); err != nil {
		return nil, err
	}
	if !validSHA.MatchString(payload.After) || !validSHA.MatchString(payload.Before) {
		return nil, errors.New("bad push")
	}
	if payload.Before == zeroSHA {
		// A new default branch has no earlier commit to compare with.
		return nil, nil
	}
	before, after := payload.Before, payload.After
	return s.checkJob("push", payload.Installation, payload.Repository, after, map[string]string{
		"checks": writeAccess, "contents": readAccess, "metadata": readAccess,
	}, func(ctx context.Context, c *RepoClient) ([]changedFile, error) {
		return c.comparedFiles(ctx, before, after)
	}), nil
}

func validTarget(install installation, repo repository) error {
	if install.ID <= 0 || repo.ID <= 0 || !validRepo.MatchString(repo.FullName) || strings.Contains(repo.FullName, "..") {
		return errors.New("bad target")
	}
	return nil
}

// checkJob creates a check run and always closes it. A run that could not finish concludes as a
// failure with fixed text, so a broken check does not read as a pass and no internal error
// reaches the pull request.
func (s *Service) checkJob(name string, install installation, repo repository, sha string, perms map[string]string, list func(context.Context, *RepoClient) ([]changedFile, error)) *job {
	return &job{name: name, run: func(ctx context.Context) error {
		client, err := s.cfg.App.repoClient(ctx, install.ID, repo.ID, repo.FullName, perms)
		if err != nil {
			return err
		}
		id, err := client.createCheckRun(ctx, sha)
		if err != nil {
			return err
		}
		result, runErr := func() (result outcome, err error) {
			defer func() {
				if recovered := recover(); recovered != nil {
					err = errors.New("the check panicked")
				}
			}()
			evaluation, cancel := context.WithTimeout(ctx, evaluateTimeout)
			defer cancel()
			files, err := list(evaluation, client)
			if err != nil {
				return outcome{}, err
			}
			return client.evaluate(evaluation, sha, files)
		}()
		if runErr != nil {
			result = outcome{
				conclusion: "failure",
				title:      "ipso could not finish the check",
				summary:    "ipso could not finish this check, so the decision files were not all validated. Push again to retry.",
			}
		}
		if err := client.completeCheckRun(ctx, id, result); err != nil {
			return errors.Join(runErr, err)
		}
		if runErr != nil {
			return fmt.Errorf("the check did not finish: %w", runErr)
		}
		return nil
	}}
}

// deliverySet remembers recent delivery ids, so a repeated delivery does no work twice. It is in
// memory and bounded, because this service has no database. A restart forgets it, and the worst
// case is one more check run.
type deliverySet struct {
	mu    sync.Mutex
	limit int
	order []string
	known map[string]bool
}

func newDeliverySet(limit int) *deliverySet {
	return &deliverySet{limit: limit, known: make(map[string]bool, limit)}
}

// add returns false when the id is already present.
func (d *deliverySet) add(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.known[id] {
		return false
	}
	if len(d.order) >= d.limit {
		delete(d.known, d.order[0])
		d.order = d.order[1:]
	}
	d.known[id] = true
	d.order = append(d.order, id)
	return true
}

func (d *deliverySet) forget(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.known, id)
	for i, known := range d.order {
		if known == id {
			d.order = append(d.order[:i], d.order[i+1:]...)
			return
		}
	}
}
