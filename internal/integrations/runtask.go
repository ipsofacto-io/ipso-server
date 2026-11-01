package integrations

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ipsofacto-io/ipso/pkg/plancheck"
)

const (
	runTaskPath    = "/runtasks/hcp-terraform"
	runTaskHeader  = "X-TFC-Task-Signature"
	maxRunTaskBody = 1 << 20
	maxTokenBytes  = 8192
	// runTaskJobTimeout stays inside the 10 minutes HCP Terraform waits for a first update.
	runTaskJobTimeout = 8 * time.Minute

	// DefaultHCPHost is the API host of HCP Terraform.
	DefaultHCPHost = "app.terraform.io"
	// DefaultPlanHost is where HCP Terraform redirects a plan download.
	DefaultPlanHost = "archivist.terraform.io"

	stagePrePlan   = "pre_plan"
	stagePostPlan  = "post_plan"
	stagePreApply  = "pre_apply"
	stagePostApply = "post_apply"

	statusPassed = "passed"
	statusFailed = "failed"
)

var (
	validTaskResult = regexp.MustCompile(`^taskrs-[0-9A-Za-z]{1,64}$`)
	validRun        = regexp.MustCompile(`^run-[0-9A-Za-z]{1,64}$`)
	validPlanPath   = regexp.MustCompile(`^/api/v2/(plans/plan-[0-9A-Za-z]{1,64}|runs/run-[0-9A-Za-z]{1,64}/plan)/json-output$`)
	validResultPath = regexp.MustCompile(`^/api/v2/task-results/[0-9A-Za-z-]{1,64}/callback$`)
	validHost       = regexp.MustCompile(`^[0-9A-Za-z.-]+(:[0-9]+)?$`)
)

// PlanEvaluator is a verified policy bundle. *plancheck.Bundle is the implementation.
type PlanEvaluator interface {
	Evaluate(r io.Reader, env string, now time.Time) (plancheck.Report, error)
}

// RunTaskConfig is what the run task service needs.
type RunTaskConfig struct {
	HMACKey []byte
	Bundle  PlanEvaluator
	// Env limits the checks to one environment, as --env does. Empty evaluates every plan check in force.
	Env string
	// APIHost is the only host that receives the run's access token. Empty means DefaultHCPHost.
	APIHost string
	// PlanHosts are the hosts a plan download may redirect to, besides APIHost. No token goes there.
	// Nil means DefaultPlanHost.
	PlanHosts []string
	Logger    *slog.Logger
}

// RunTaskService verifies run task requests and answers them on a bounded queue (ADR-0065).
type RunTaskService struct {
	cfg    RunTaskConfig
	jobs   *Service
	client *http.Client
	now    func() time.Time
	// wait is how long a plan that is not ready waits, and the base of the callback backoff.
	wait time.Duration
}

// NewRunTaskService returns a service. Run its workers with Run before serving Handler.
// The client refuses redirects, so an access token only ever reaches the API host.
func NewRunTaskService(cfg RunTaskConfig) *RunTaskService {
	if cfg.APIHost == "" {
		cfg.APIHost = DefaultHCPHost
	}
	if cfg.PlanHosts == nil {
		cfg.PlanHosts = []string{DefaultPlanHost}
	}
	return &RunTaskService{
		cfg:  cfg,
		jobs: &Service{cfg: Config{Logger: cfg.Logger}, queue: make(chan job, queueSize), seen: newDeliverySet(seenDeliveries), timeout: runTaskJobTimeout},
		client: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now:  time.Now,
		wait: 5 * time.Second,
	}
}

// Run works the queue until ctx ends.
func (s *RunTaskService) Run(ctx context.Context) { s.jobs.Run(ctx) }

// Handler serves POST /runtasks/hcp-terraform.
func (s *RunTaskService) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+runTaskPath, s.receive)
	return mux
}

// runTaskRequest holds the fields of the request that this service reads. The access token is kept
// in memory for the job and never logged.
type runTaskRequest struct {
	PayloadVersion int    `json:"payload_version"`
	Stage          string `json:"stage"`
	AccessToken    string `json:"access_token"`
	Capabilities   struct {
		Outcomes bool `json:"outcomes"`
	} `json:"capabilities"`
	PlanURL     string `json:"plan_json_api_url"`
	CallbackURL string `json:"task_result_callback_url"`
	TaskResult  string `json:"task_result_id"`
	Run         string `json:"run_id"`
}

// receive checks the signature over the raw bytes before anything parses them. HCP Terraform answers a
// status other than 200 by triggering the task again, so a signed request that cannot become a job gets
// 200 and does no work. That includes the test request sent when a run task is created. A real run in
// that state is never reported, so HCP Terraform times it out, and a mandatory task blocks the apply.
func (s *RunTaskService) receive(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRunTaskBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !validTaskSignature(s.cfg.HMACKey, body, r.Header.Get(runTaskHeader)) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var request runTaskRequest
	if err := json.Unmarshal(body, &request); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	callback, ok := s.callbackURL(request)
	if !ok {
		s.cfg.Logger.Info("run task request needs no work")
		w.WriteHeader(http.StatusOK)
		return
	}
	if !s.jobs.seen.add(request.TaskResult) {
		w.WriteHeader(http.StatusOK)
		return
	}
	next := job{delivery: request.TaskResult, name: "run task", run: func(ctx context.Context) error {
		return s.runJob(ctx, request, callback)
	}}
	select {
	case s.jobs.queue <- next:
		w.WriteHeader(http.StatusOK)
	default:
		// HCP Terraform triggers the task again.
		s.jobs.seen.forget(request.TaskResult)
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}
}

// callbackURL reports whether the request can be answered: a supported version, ids of the expected
// form, a token, and a callback on the API host. A token is never sent anywhere else.
func (s *RunTaskService) callbackURL(request runTaskRequest) (string, bool) {
	if request.PayloadVersion != 1 || !validTaskResult.MatchString(request.TaskResult) || !validRun.MatchString(request.Run) {
		return "", false
	}
	if request.AccessToken == "" || len(request.AccessToken) > maxTokenBytes {
		return "", false
	}
	return parseAPIURL(request.CallbackURL, s.cfg.APIHost, validResultPath)
}

// parseAPIURL checks a URL from a request and builds a new one from the configured host and the checked
// path, so nothing but that path comes from the request.
func parseAPIURL(raw, host string, path *regexp.Regexp) (string, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host != host || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false
	}
	checked := parsed.Path
	if !path.MatchString(checked) {
		return "", false
	}
	return (&url.URL{Scheme: "https", Host: host, Path: checked}).String(), true
}

func validTaskSignature(key, body []byte, header string) bool {
	if len(key) == 0 {
		return false
	}
	given, err := hex.DecodeString(header)
	if err != nil || len(given) == 0 {
		return false
	}
	mac := hmac.New(sha512.New, key)
	mac.Write(body)
	return hmac.Equal(given, mac.Sum(nil))
}

// runJob evaluates the plan and always tries to report. A run that cannot finish is reported as failed
// with fixed text, so a broken evaluation does not read as a pass and no internal error reaches the run.
func (s *RunTaskService) runJob(ctx context.Context, request runTaskRequest, callback string) error {
	result, runErr := func() (result taskResult, err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = errors.New("the evaluation panicked")
			}
		}()
		return s.evaluate(ctx, request)
	}()
	if runErr != nil {
		result = taskResult{status: statusFailed, message: "ipso could not finish this check, so the plan was not evaluated. Run the plan again to retry."}
	}
	if err := s.report(ctx, request, callback, result); err != nil {
		return errors.Join(runErr, err)
	}
	if runErr != nil {
		return fmt.Errorf("the evaluation did not finish: %w", runErr)
	}
	s.cfg.Logger.Info("run task evaluated", "task_result", request.TaskResult, "run", request.Run, "status", result.status,
		"plan_sha256", result.planSHA256, "checks", result.checks, "failed", result.failed)
	return nil
}

func (s *RunTaskService) evaluate(ctx context.Context, request runTaskRequest) (taskResult, error) {
	if request.Stage != stagePostPlan && request.Stage != stagePreApply {
		return taskResult{status: statusFailed, message: "ipso evaluates a plan, so attach this run task to the post-plan or the pre-apply stage."}, nil
	}
	planURL, ok := parseAPIURL(request.PlanURL, s.cfg.APIHost, validPlanPath)
	if !ok {
		return taskResult{}, errors.New("the plan URL is not on the API host")
	}
	plan, err := s.openPlan(ctx, planURL, request.AccessToken)
	if err != nil {
		return taskResult{}, err
	}
	defer func() { _ = plan.Close() }()
	report, err := s.cfg.Bundle.Evaluate(plan, s.cfg.Env, s.now())
	if err != nil {
		// The text of this error can quote the plan. The code cannot.
		return taskResult{}, fmt.Errorf("the plan could not be evaluated: %s", codeOr(plancheck.Code(err), "no code"))
	}
	return resultOf(report, request.Capabilities.Outcomes), nil
}

func codeOr(code, fallback string) string {
	if code == "" {
		return fallback
	}
	return code
}

// openPlan asks the API for the plan and follows one redirect, without the token, to an allowed host.
// A plan that is not ready answers 204, and it gets a few more tries.
func (s *RunTaskService) openPlan(ctx context.Context, planURL, token string) (io.ReadCloser, error) {
	const attempts = 6
	for attempt := range attempts {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, planURL, nil)
		if err != nil {
			return nil, errors.New("the plan request cannot be built")
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := s.client.Do(request)
		if err != nil {
			return nil, withoutURL("the plan request failed", err)
		}
		switch response.StatusCode {
		case http.StatusOK:
			return response.Body, nil
		case http.StatusNoContent:
			_ = response.Body.Close()
			if attempt == attempts-1 {
				return nil, errors.New("the plan is not ready")
			}
			if err := sleepContext(ctx, s.wait); err != nil {
				return nil, err
			}
		case http.StatusTemporaryRedirect, http.StatusFound, http.StatusSeeOther:
			location := response.Header.Get("Location")
			_ = response.Body.Close()
			return s.followPlanRedirect(ctx, location)
		default:
			_ = response.Body.Close()
			return nil, fmt.Errorf("the plan request answered %d", response.StatusCode)
		}
	}
	return nil, errors.New("the plan is not ready")
}

func (s *RunTaskService) followPlanRedirect(ctx context.Context, location string) (io.ReadCloser, error) {
	target, err := url.Parse(location)
	if err != nil || target.Scheme != "https" || target.User != nil {
		return nil, errors.New("the plan redirect is not HTTPS")
	}
	if target.Host != s.cfg.APIHost && !slices.Contains(s.cfg.PlanHosts, target.Host) {
		return nil, errors.New("the plan redirect names a host that is not allowed")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, errors.New("the plan download cannot be built")
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, withoutURL("the plan download failed", err)
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, fmt.Errorf("the plan download answered %d", response.StatusCode)
	}
	return response.Body, nil
}

// withoutURL drops the client's error text, because it quotes the URL, and a plan download URL is itself
// a credential. Only whether the request timed out survives.
func withoutURL(message string, err error) error {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return fmt.Errorf("%s: timed out", message)
	}
	return errors.New(message)
}

func sleepContext(ctx context.Context, wait time.Duration) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// report sends the result. It tries three times when the failure may pass, and never follows a redirect.
func (s *RunTaskService) report(ctx context.Context, request runTaskRequest, callback string, result taskResult) error {
	body, err := json.Marshal(result.document())
	if err != nil {
		return errors.New("the result cannot be encoded")
	}
	const attempts = 3
	var last error
	for attempt := range attempts {
		if attempt > 0 {
			if err := sleepContext(ctx, s.wait*time.Duration(attempt)); err != nil {
				return errors.Join(last, err)
			}
		}
		retry, err := s.patch(ctx, callback, request.AccessToken, body)
		if err == nil {
			return nil
		}
		last = err
		if !retry {
			return err
		}
	}
	return last
}

func (s *RunTaskService) patch(ctx context.Context, callback, token string, body []byte) (retry bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPatch, callback, strings.NewReader(string(body)))
	if err != nil {
		return false, errors.New("the callback cannot be built")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", jsonAPI)
	response, err := s.client.Do(request)
	if err != nil {
		return true, withoutURL("the callback failed", err)
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxAPIBody))
	switch {
	case response.StatusCode >= 200 && response.StatusCode < 300:
		return false, nil
	case response.StatusCode >= 500 || response.StatusCode == http.StatusTooManyRequests:
		return true, fmt.Errorf("the callback answered %d", response.StatusCode)
	default:
		return false, fmt.Errorf("the callback answered %d", response.StatusCode)
	}
}
