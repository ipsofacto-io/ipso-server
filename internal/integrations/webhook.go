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
	"go.opentelemetry.io/otel/trace"

	"github.com/ipsofacto-io/ipso-server/internal/telemetry"
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
	// advisoryQueueSize and advisoryWorkerCount bound the advisory jobs of open pull requests, which wait on a
	// model like a merged pull request job and have a lane of their own, so a push never delays the extraction
	// of a merged pull request (ADR-0174). A full lane drops the advisory job and the check run still runs.
	advisoryQueueSize   = 64
	advisoryWorkerCount = 1
	// advisoryLookupTimeout bounds the read of the opt-in while GitHub waits for the answer, after the tenant
	// lookup, so the two stay inside the 10 seconds of a delivery.
	advisoryLookupTimeout = 2 * time.Second
	// advisoryKey is added to the delivery id to name the advisory job in the seen set, so a failure of the
	// check run never repeats the advisory job on a redelivery, nor the reverse.
	advisoryKey = "/advisory"
	// lookupTimeout bounds the tenant lookup of a delivery. GitHub gives a delivery 10 seconds.
	lookupTimeout = 5 * time.Second
	// unbindTimeout bounds the removal of a binding, which asks GitHub and then the database while GitHub waits
	// for the answer (ADR-0125).
	unbindTimeout = 8 * time.Second
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
	// RepositoryID is the numeric id of the repository, which a log line names instead of Repo: the owner of a
	// repository can be a person (ADR-0012, ADR-0155).
	RepositoryID int64
	Number       int
	Client       *RepoClient
}

// OpenPullRequest is a pull request that was opened, updated, reopened or marked ready in a repository the tenant
// opted in to llm-advisory checks, and a client limited to reading its contents and its files (ADR-0174). HeadSHA
// is the head the delivery names. The hook reads the pull request again and stops when the head moved.
type OpenPullRequest struct {
	// Tenant is the tenant the installation is bound to. It comes from the mapping and never from the payload
	// (ADR-0101).
	Tenant         uuid.UUID
	InstallationID int64
	Repo           string
	RepositoryID   int64
	Number         int
	HeadSHA        string
	Client         *RepoClient
}

// Config is what the service needs. OnMerged is optional. When it is nil, a merged pull request
// mints no token and starts no work (ADR-0062). ipso-server webhooks sets it when an LLM gateway is
// configured (ADR-0103).
//
// Tenants maps the installation of a delivery to its tenant, and reports false for an installation no
// tenant owns. A delivery that would start work is answered 403 and starts nothing when the installation
// has no tenant, and 503 when the lookup fails. Without Tenants every such delivery is refused (ADR-0101).
//
// Unbind removes the binding of an installation that GitHub deleted, and reports the tenant that held it, or
// false when no tenant did. It is called only after GitHub confirms that the installation is gone. Without it an
// uninstall delivery is answered 503 (ADR-0125).
type Config struct {
	App           *App
	WebhookSecret []byte
	Logger        *slog.Logger
	Tenants       func(ctx context.Context, installationID int64) (uuid.UUID, bool, error)
	Unbind        func(ctx context.Context, installationID int64) (uuid.UUID, bool, error)
	OnMerged      func(context.Context, MergedPullRequest) error
	// AdvisoryEnabled reports whether the tenant opted the repository in to llm-advisory checks, and
	// OnPullRequest runs the advisory job of an open pull request (ADR-0174). The service sets neither without
	// the other: when either is nil, a pull request starts no advisory job. The opt-in is read when the delivery
	// arrives and again before the job mints a token, so a repository that is not on the list mints nothing.
	AdvisoryEnabled func(ctx context.Context, tenant uuid.UUID, repo string) (bool, error)
	OnPullRequest   func(context.Context, OpenPullRequest) error
	// Telemetry observes the requests and the jobs of the service (ADR-0155). Nil observes nothing.
	Telemetry *telemetry.Telemetry
}

// Service verifies webhooks and runs their jobs on a bounded queue.
type Service struct {
	cfg   Config
	queue chan job
	// merged queues the merged pull request jobs, which wait on a model and have workers of their own.
	merged chan job
	// advisory queues the advisory jobs of open pull requests, which wait on a model and have a worker of
	// their own (ADR-0174).
	advisory chan job
	seen     *deliverySet
	// timeout bounds one job. Zero means jobTimeout, or mergedJobTimeout for a job that waits on a model.
	timeout time.Duration
}

// lane is the queue a job waits in. A merged pull request job and an advisory job wait on a model, and
// each has workers of its own and the longer bound.
type lane int

const (
	laneCheck lane = iota
	laneMerged
	laneAdvisory
)

type job struct {
	// delivery is the key of the job in the seen set: the delivery id, with advisoryKey added for an
	// advisory job, or the task result id of a run task.
	delivery string
	name     string
	// kind is the ipso.job.kind of the job: check, merged_pr, advisory_pr or runtask.
	kind string
	lane lane
	// installation is the one the signed payload names. tenant is what the mapping says it belongs to,
	// set by receive before the job is queued. A job never takes its tenant from a payload.
	installation int64
	tenant       uuid.UUID
	// received is when the job was queued, and span is the request that queued it. The telemetry of the job
	// counts from the first and hangs under the second.
	received time.Time
	span     trace.SpanContext
	run      func(ctx context.Context, tenant uuid.UUID) error
}

// NewService returns a service. Run its workers with Run before serving Handler.
func NewService(cfg Config) *Service {
	return &Service{
		cfg:      cfg,
		queue:    make(chan job, queueSize),
		merged:   make(chan job, queueSize),
		advisory: make(chan job, advisoryQueueSize),
		seen:     newDeliverySet(seenDeliveries),
	}
}

// Run works the queues until ctx ends, then finishes what was queued, for at most drainTimeout. The check
// runs, the merged pull request jobs and the advisory jobs have workers of their own.
func (s *Service) Run(ctx context.Context) {
	jobContext, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	var workers sync.WaitGroup
	stop := make(chan struct{})
	for _, lane := range []struct {
		queue chan job
		count int
	}{{s.queue, workerCount}, {s.merged, mergedWorkerCount}, {s.advisory, advisoryWorkerCount}} {
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
		if next.lane != laneCheck {
			limit = mergedJobTimeout
		}
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	ctx, end := s.cfg.Telemetry.StartJob(telemetry.Remote(ctx, next.span), next.kind, next.tenant, next.received)
	err := func() (err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = telemetry.ErrPanic
			}
		}()
		return next.run(ctx, next.tenant)
	}()
	end(err)
	if err != nil {
		s.seen.forget(next.delivery)
		s.cfg.Logger.ErrorContext(ctx, "webhook job failed", "delivery", next.delivery, "job", next.name, "error", err)
		return
	}
	s.cfg.Logger.InfoContext(ctx, "webhook job finished", "delivery", next.delivery, "job", next.name)
}

// Handler serves POST /webhooks/github. The signature is checked over the raw bytes before any
// parsing. The handler answers before the job runs, because GitHub gives a delivery 10 seconds.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+webhookPath, s.receive)
	return mux
}

func (s *Service) receive(w http.ResponseWriter, r *http.Request) {
	// A job is measured from the moment its delivery arrived, before the body, the signature and the mapping
	// lookup, which can take seconds. The objective of section 15 for a check result counts from here.
	received := time.Now()
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
	event := r.Header.Get("X-GitHub-Event")
	if event == "installation" {
		s.receiveInstallation(r.Context(), w, delivery, body)
		return
	}
	work, err := s.route(event, body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if work.main == nil && work.advisory == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	// The tenant of a delivery is the one the mapping gives its installation. An installation nobody
	// bound starts nothing, and its delivery is not remembered, so a redelivery after the operator binds
	// it is worked (ADR-0101).
	tenant, bound, err := s.tenantOf(r.Context(), work.installation)
	if err != nil {
		s.cfg.Logger.ErrorContext(r.Context(), "webhook tenant lookup failed", "delivery", delivery, "installation", work.installation, "error", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !bound {
		s.cfg.Logger.WarnContext(r.Context(), "webhook from an installation no tenant owns", "delivery", delivery, "installation", work.installation)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	telemetry.SetTenant(r.Context(), tenant)
	stamp := func(next *job, key string) {
		next.tenant = tenant
		next.delivery = key
		next.received = received
		next.span = telemetry.SpanContext(r.Context())
	}
	if work.main != nil {
		stamp(work.main, delivery)
		if s.seen.add(delivery) {
			queue := s.queue
			if work.main.lane == laneMerged {
				queue = s.merged
			}
			select {
			case queue <- *work.main:
			default:
				// GitHub records the failed delivery, and it can be redelivered. The advisory job waits for it.
				s.seen.forget(delivery)
				http.Error(w, "busy", http.StatusServiceUnavailable)
				return
			}
		}
	}
	if work.advisory != nil {
		stamp(&work.advisory.job, delivery+advisoryKey)
		s.queueAdvisory(r.Context(), *work.advisory)
	}
	w.WriteHeader(http.StatusAccepted)
}

// queueAdvisory queues the advisory job of a delivery under a seen key of its own. A repository the tenant did
// not opt in queues nothing and mints nothing (ADR-0174). A failed read of the opt-in or a full lane drops the
// job and logs it, and the delivery is answered as its other work says: the advisory job is best effort, and
// the next push is evaluated. The log names the delivery and never the repository.
func (s *Service) queueAdvisory(ctx context.Context, next advisoryJob) {
	lookup, cancel := context.WithTimeout(ctx, advisoryLookupTimeout)
	enabled, err := s.cfg.AdvisoryEnabled(lookup, next.job.tenant, next.repo)
	cancel()
	switch {
	case err != nil:
		s.cfg.Logger.ErrorContext(ctx, "webhook advisory job dropped", "delivery", next.job.delivery, "reason", "the opt-in read failed")
		return
	case !enabled:
		return
	case !s.seen.add(next.job.delivery):
		return
	}
	select {
	case s.advisory <- next.job:
	default:
		s.seen.forget(next.job.delivery)
		s.cfg.Logger.WarnContext(ctx, "webhook advisory job dropped", "delivery", next.job.delivery, "reason", "the lane is full")
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

// receiveInstallation removes the binding of an installation that its account uninstalled (ADR-0125). The work
// is one read of GitHub and one short transaction, so it runs while GitHub waits and the answer says whether it
// was done, which lets an operator redeliver a failed delivery. Every other action of the event needs no work: a
// suspended installation keeps its binding, and GitHub refuses it tokens meanwhile.
func (s *Service) receiveInstallation(ctx context.Context, w http.ResponseWriter, delivery string, body []byte) {
	var payload struct {
		Action       string       `json:"action"`
		Installation installation `json:"installation"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if payload.Action != "deleted" {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	id := payload.Installation.ID
	if id <= 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.Unbind == nil {
		s.cfg.Logger.ErrorContext(ctx, "webhook service cannot remove a binding", "delivery", delivery, "installation", id)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, unbindTimeout)
	defer cancel()
	// Every other delivery starts only work that GitHub then enforces with a token of its own. Nothing enforces
	// a removal, so the App asks GitHub itself, and a delivery forged with a stolen secret removes nothing.
	gone, err := s.installationGone(ctx, id)
	if err != nil {
		s.cfg.Logger.ErrorContext(ctx, "webhook installation check failed", "delivery", delivery, "installation", id, "error", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !gone {
		s.cfg.Logger.WarnContext(ctx, "webhook says an installation was deleted and GitHub still has it", "delivery", delivery, "installation", id)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	tenant, removed, err := s.cfg.Unbind(ctx, id)
	if err != nil {
		s.cfg.Logger.ErrorContext(ctx, "webhook binding removal failed", "delivery", delivery, "installation", id, "error", "the removal failed")
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if removed {
		s.cfg.Logger.InfoContext(ctx, "webhook removed the binding of a deleted installation", "delivery", delivery, "installation", id, "tenant", tenant)
	} else {
		s.cfg.Logger.InfoContext(ctx, "webhook deleted installation had no binding", "delivery", delivery, "installation", id)
	}
	w.WriteHeader(http.StatusAccepted)
}

// installationGone asks GitHub, as the App, whether an installation still exists. Not found means it is gone.
func (s *Service) installationGone(ctx context.Context, id int64) (bool, error) {
	_, err := s.cfg.App.InstallationAccount(ctx, id)
	switch {
	case errors.Is(err, ErrNotFound):
		return true, nil
	case err != nil:
		return false, err
	default:
		return false, nil
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

// routed is the work of one signed delivery: a job on the check or the merged lane, and an advisory job. Either
// can be nil, and both come from the one installation the payload names.
type routed struct {
	installation int64
	main         *job
	advisory     *advisoryJob
}

// advisoryJob is an advisory job and the lowercase owner/name whose opt-in decides whether it is queued.
type advisoryJob struct {
	repo string
	job  job
}

// route turns a signed event into its work. No job means the event needs no work. An error means a
// handled event is malformed.
func (s *Service) route(event string, body []byte) (routed, error) {
	switch event {
	case "pull_request":
		return s.routePullRequest(body)
	case "push":
		next, err := s.routePush(body)
		if err != nil || next == nil {
			return routed{}, err
		}
		return routed{installation: next.installation, main: next}, nil
	default:
		return routed{}, nil
	}
}

func (s *Service) routePullRequest(body []byte) (routed, error) {
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
		return routed{}, errors.New("not JSON")
	}
	switch payload.Action {
	case "opened", "synchronize", "reopened", "ready_for_review":
		if err := validTarget(payload.Installation, payload.Repository); err != nil {
			return routed{}, err
		}
		if !validSHA.MatchString(payload.PullRequest.Head.SHA) || payload.Number <= 0 {
			return routed{}, errors.New("bad pull request")
		}
		number, sha := payload.Number, payload.PullRequest.Head.SHA
		work := routed{installation: payload.Installation.ID, advisory: s.advisoryJob(payload.Installation, payload.Repository, number, sha)}
		// Marking a draft ready changes no commit, so the check run of its head already ran.
		if payload.Action != "ready_for_review" {
			work.main = s.checkJob("pull_request", payload.Installation, payload.Repository, sha, map[string]string{
				"checks": writeAccess, "contents": readAccess, "metadata": readAccess, "pull_requests": readAccess,
			}, func(ctx context.Context, c *RepoClient) ([]changedFile, error) {
				return c.pullRequestFiles(ctx, number)
			})
		}
		return work, nil
	case "closed":
		if !payload.PullRequest.Merged || s.cfg.OnMerged == nil {
			return routed{}, nil
		}
		if err := validTarget(payload.Installation, payload.Repository); err != nil {
			return routed{}, err
		}
		if payload.Number <= 0 {
			return routed{}, errors.New("bad pull request")
		}
		return routed{installation: payload.Installation.ID, main: &job{name: "merged", kind: "merged_pr", lane: laneMerged, installation: payload.Installation.ID, run: func(ctx context.Context, tenant uuid.UUID) error {
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
				RepositoryID:   payload.Repository.ID,
				Number:         payload.Number,
				Client:         client,
			})
		}}}, nil
	default:
		return routed{}, nil
	}
}

// advisoryJob is the advisory job of an open pull request, or nil when the service has no advisory hook. The job
// reads the opt-in again before it mints a token, so a repository removed from the list while the job waited
// mints nothing. The token reads contents, metadata and pull requests, and writes nothing (ADR-0174).
func (s *Service) advisoryJob(install installation, repo repository, number int, sha string) *advisoryJob {
	if s.cfg.AdvisoryEnabled == nil || s.cfg.OnPullRequest == nil {
		return nil
	}
	name := strings.ToLower(repo.FullName)
	return &advisoryJob{repo: name, job: job{name: "advisory", kind: "advisory_pr", lane: laneAdvisory, installation: install.ID, run: func(ctx context.Context, tenant uuid.UUID) error {
		enabled, err := s.cfg.AdvisoryEnabled(ctx, tenant, name)
		if err != nil || !enabled {
			return err
		}
		client, err := s.cfg.App.repoClient(ctx, install.ID, repo.ID, repo.FullName, map[string]string{
			"contents": readAccess, "metadata": readAccess, "pull_requests": readAccess,
		})
		if err != nil {
			return err
		}
		return s.cfg.OnPullRequest(ctx, OpenPullRequest{
			Tenant:         tenant,
			InstallationID: install.ID,
			Repo:           repo.FullName,
			RepositoryID:   repo.ID,
			Number:         number,
			HeadSHA:        sha,
			Client:         client,
		})
	}}}
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
	return &job{name: name, kind: "check", installation: install.ID, run: func(ctx context.Context, _ uuid.UUID) error {
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
