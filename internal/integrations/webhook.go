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

	"github.com/google/uuid"
)

const (
	webhookPath    = "/webhooks/github"
	maxWebhookBody = 5 << 20
	queueSize      = 256
	workerCount    = 4
	jobTimeout     = 2 * time.Minute
	// mergedWorkerCount works the merged pull request jobs apart from the check runs, so a slow model never
	// delays a check run (ADR-0103).
	mergedWorkerCount = 2
	// mergedJobTimeout bounds a merged pull request job. The gateway gives each route 90 seconds, and up to 600
	// for a model served on CPU (ADR-0088), and tries the next route when one fails, so the bound of a check
	// run would cut a call that failed over to a second route and lose the tokens it spent.
	mergedJobTimeout = 15 * time.Minute
	// lookupTimeout bounds the tenant lookup of a delivery. GitHub gives a delivery 10 seconds.
	lookupTimeout = 5 * time.Second
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
	// Tenant is the tenant the installation is bound to. It comes from the mapping and never from the
	// payload (ADR-0101).
	Tenant         uuid.UUID
	InstallationID int64
	Repo           string
	Number         int
	Client         *RepoClient
}

// Config is what the service needs. OnMerged is optional. When it is nil, a merged pull request
// mints no token and starts no work (ADR-0062). ipso-server webhooks sets it when an LLM gateway is
// configured (ADR-0103).
//
// Tenants maps the installation of a delivery to its tenant, and reports false for an installation no
// tenant owns. A delivery that would start work is answered 403 and starts nothing when the installation
// has no tenant, and 503 when the lookup fails. Without Tenants every such delivery is refused (ADR-0101).
type Config struct {
	App           *App
	WebhookSecret []byte
	Logger        *slog.Logger
	Tenants       func(ctx context.Context, installationID int64) (uuid.UUID, bool, error)
	OnMerged      func(context.Context, MergedPullRequest) error
}

// Service verifies webhooks and runs their jobs on a bounded queue.
type Service struct {
	cfg   Config
	queue chan job
	// merged queues the merged pull request jobs, which wait on a model and have workers of their own.
	merged chan job
	seen   *deliverySet
	// timeout bounds one job. Zero means jobTimeout, or mergedJobTimeout for a merged pull request.
	timeout time.Duration
}

type job struct {
	delivery string
	name     string
	// merged marks a merged pull request job, which runs on its own workers and under its own bound.
	merged bool
	// installation is the one the signed payload names. tenant is what the mapping says it belongs to,
	// set by receive before the job is queued. A job never takes its tenant from a payload.
	installation int64
	tenant       uuid.UUID
	run          func(ctx context.Context, tenant uuid.UUID) error
}

// NewService returns a service. Run its workers with Run before serving Handler.
func NewService(cfg Config) *Service {
	return &Service{cfg: cfg, queue: make(chan job, queueSize), merged: make(chan job, queueSize), seen: newDeliverySet(seenDeliveries)}
}

// Run works the queues until ctx ends, then finishes what was queued, for at most drainTimeout. The check
// runs and the merged pull request jobs have workers of their own.
func (s *Service) Run(ctx context.Context) {
	jobContext, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	var workers sync.WaitGroup
	stop := make(chan struct{})
	for _, lane := range []struct {
		queue chan job
		count int
	}{{s.queue, workerCount}, {s.merged, mergedWorkerCount}} {
		for range lane.count {
			workers.Go(func() {
				for {
					select {
					case next := <-lane.queue:
						s.work(jobContext, next)
					case <-stop:
						for {
							select {
							case next := <-lane.queue:
								s.work(jobContext, next)
							default:
								return
							}
						}
					}
				}
			})
		}
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
	limit := s.timeout
	if limit == 0 {
		limit = jobTimeout
		if next.merged {
			limit = mergedJobTimeout
		}
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	err := func() (err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = errors.New("the job panicked")
			}
		}()
		return next.run(ctx, next.tenant)
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
	// The tenant of a delivery is the one the mapping gives its installation. An installation nobody
	// bound starts nothing, and its delivery is not remembered, so a redelivery after the operator binds
	// it is worked (ADR-0101).
	tenant, bound, err := s.tenantOf(r.Context(), next.installation)
	if err != nil {
		s.cfg.Logger.Error("webhook tenant lookup failed", "delivery", delivery, "installation", next.installation, "error", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !bound {
		s.cfg.Logger.Warn("webhook from an installation no tenant owns", "delivery", delivery, "installation", next.installation)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	next.tenant = tenant
	next.delivery = delivery
	if !s.seen.add(delivery) {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	queue := s.queue
	if next.merged {
		queue = s.merged
	}
	select {
	case queue <- *next:
		w.WriteHeader(http.StatusAccepted)
	default:
		// GitHub records the failed delivery, and it can be redelivered.
		s.seen.forget(delivery)
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}
}

// tenantOf asks the mapping for the tenant of an installation. A service with no mapping owns no
// installation.
func (s *Service) tenantOf(ctx context.Context, installationID int64) (uuid.UUID, bool, error) {
	if s.cfg.Tenants == nil {
		return uuid.Nil, false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	tenant, bound, err := s.cfg.Tenants(ctx, installationID)
	if err != nil {
		return uuid.Nil, false, errors.New("the lookup failed")
	}
	if !bound || tenant == uuid.Nil {
		return uuid.Nil, false, nil
	}
	return tenant, true, nil
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
		return &job{name: "merged", merged: true, installation: payload.Installation.ID, run: func(ctx context.Context, tenant uuid.UUID) error {
			client, err := s.cfg.App.repoClient(ctx, payload.Installation.ID, payload.Repository.ID, payload.Repository.FullName, map[string]string{
				"metadata": readAccess, "pull_requests": readAccess,
			})
			if err != nil {
				return err
			}
			return s.cfg.OnMerged(ctx, MergedPullRequest{
				Tenant:         tenant,
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
	return &job{name: name, installation: install.ID, run: func(ctx context.Context, _ uuid.UUID) error {
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
// memory and bounded. A restart forgets it, and the worst case is one more check run, or one more read of a
// discussion that sends the model nothing, because a comment already turned into a proposal is not sent again.
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
