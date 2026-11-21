// Package runtask evaluates the plan of an HCP Terraform or Terraform Enterprise run against a signed
// policy bundle (ADR-0065). It has two halves. The receiver verifies a signed run task request and hands a
// Task to its caller. The runner takes a Task, downloads the plan with the run's access token, evaluates
// it, and reports the result to the run. `ipso-server runtasks` composes both in one process. The BYOC
// data plane composes them in two, the receiver in the control plane and the runner in the customer's
// cluster, so the plan is read only where the runner runs (ADR-0144).
package runtask

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
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
	// Path is the route of the run task receiver.
	Path = "/runtasks/hcp-terraform"
	// Header carries the HMAC-SHA512 of the request body.
	Header = "X-TFC-Task-Signature"
	// MaxBody is the largest request body the receiver reads.
	MaxBody       = 1 << 20
	maxTokenBytes = 8192
	// JobTimeout stays inside the 10 minutes HCP Terraform waits for a first update. A caller that runs a
	// task bounds it with this.
	JobTimeout = 8 * time.Minute
	// evaluateTimeout leaves the rest of JobTimeout to report, including a failure.
	evaluateTimeout = 7 * time.Minute
	apiTimeout      = 30 * time.Second
	maxAPIBody      = 8 << 20

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

	// runStages are the stages HCP Terraform documents for a run. A request with any other stage, or
	// none, does no work. That covers the request sent when a task is saved (ADR-0080).
	runStages = []string{stagePrePlan, stagePostPlan, stagePreApply, stagePostApply}
)

// ValidHost reports whether host is a host name with an optional port, as an API host or a plan host is.
func ValidHost(host string) bool { return validHost.MatchString(host) }

// PlanEvaluator is a verified policy bundle. *plancheck.Bundle is the implementation.
type PlanEvaluator interface {
	Evaluate(r io.Reader, env string, now time.Time) (plancheck.Report, error)
}

// Task is the part of a run task request that a runner needs. The access token is kept in memory for the
// job and never logged. A runner that receives a Task from another process calls Check, whatever that
// process did before.
type Task struct {
	Stage       string `json:"stage"`
	AccessToken string `json:"access_token"`
	Outcomes    bool   `json:"outcomes"`
	PlanURL     string `json:"plan_json_api_url"`
	CallbackURL string `json:"task_result_callback_url"`
	TaskResult  string `json:"task_result_id"`
	Run         string `json:"run_id"`
}

// Check reports whether the task can be answered: a stage of a run, ids of the expected form, a token, and a
// callback on apiHost. It returns that callback rebuilt from apiHost and the checked path, so a token is
// never sent anywhere else.
func (t Task) Check(apiHost string) (callback string, ok bool) {
	if !slices.Contains(runStages, t.Stage) {
		return "", false
	}
	if !validTaskResult.MatchString(t.TaskResult) || !validRun.MatchString(t.Run) {
		return "", false
	}
	if t.AccessToken == "" || len(t.AccessToken) > maxTokenBytes {
		return "", false
	}
	return parseAPIURL(t.CallbackURL, apiHost, validResultPath)
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

// ReceiverConfig is what the receiver needs.
type ReceiverConfig struct {
	HMACKey []byte
	// APIHost is the only host a callback may name. Empty means DefaultHCPHost.
	APIHost string
	Logger  *slog.Logger
}

// receiver verifies run task requests and hands their tasks on.
type receiver struct {
	cfg    ReceiverConfig
	accept func(Task) bool
}

// NewHandler serves POST Path. It checks the signature over the raw bytes before anything parses them,
// then hands the task to accept. accept returns true when it took the task, or when the task is one it has
// already taken, and false when it has no room, which answers 503 so that HCP Terraform triggers the task
// again.
func NewHandler(cfg ReceiverConfig, accept func(Task) bool) http.Handler {
	if cfg.APIHost == "" {
		cfg.APIHost = DefaultHCPHost
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+Path, (&receiver{cfg: cfg, accept: accept}).receive)
	return mux
}

// request holds the fields of the request that this package reads.
type request struct {
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
// status other than 200 by triggering the task again, so a signed request that cannot become a task gets
// 200 and does no work. That includes the request sent when a run task is saved. A real run in
// that state is never reported, so HCP Terraform times it out, and a mandatory task blocks the apply.
func (r *receiver) receive(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, MaxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !validTaskSignature(r.cfg.HMACKey, body, req.Header.Get(Header)) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var parsed request
	if err := json.Unmarshal(body, &parsed); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	task := Task{
		Stage:       parsed.Stage,
		AccessToken: parsed.AccessToken,
		Outcomes:    parsed.Capabilities.Outcomes,
		PlanURL:     parsed.PlanURL,
		CallbackURL: parsed.CallbackURL,
		TaskResult:  parsed.TaskResult,
		Run:         parsed.Run,
	}
	if _, ok := task.Check(r.cfg.APIHost); !ok || parsed.PayloadVersion != 1 {
		r.cfg.Logger.Info("run task request needs no work", "stage", cleanText(parsed.Stage))
		w.WriteHeader(http.StatusOK)
		return
	}
	if !r.accept(task) {
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
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

// RunnerConfig is what a runner needs.
type RunnerConfig struct {
	Bundle PlanEvaluator
	// Env limits the checks to one environment, as --env does. Empty evaluates every plan check in force.
	Env string
	// APIHost is the only host that receives the run's access token. Empty means DefaultHCPHost.
	APIHost string
	// PlanHosts are the hosts a plan download may redirect to, besides APIHost. No token goes there.
	// Nil means DefaultPlanHost.
	PlanHosts []string
	// RootCAs are the trust anchors for the API host and the plan hosts, for a Terraform Enterprise whose
	// certificate a private authority signed. Nil means the system roots. It never applies to any other
	// connection of the process.
	RootCAs *x509.CertPool
	Logger  *slog.Logger
}

// Runner evaluates tasks. It trusts nothing in a task beyond what Check accepts: every URL is rebuilt from
// its own configured host, and the policy bundle is its own.
type Runner struct {
	cfg    RunnerConfig
	client *http.Client
	now    func() time.Time
	// wait is how long a plan that is not ready waits, and the base of the callback backoff.
	wait time.Duration
	// evaluateLimit bounds reading and evaluating one plan.
	evaluateLimit time.Duration
}

// NewRunner returns a runner. Its client refuses redirects, so an access token only ever reaches the API host.
func NewRunner(cfg RunnerConfig) *Runner {
	if cfg.APIHost == "" {
		cfg.APIHost = DefaultHCPHost
	}
	if cfg.PlanHosts == nil {
		cfg.PlanHosts = []string{DefaultPlanHost}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if cfg.RootCAs != nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs}
		client.Transport = transport
	}
	return &Runner{
		cfg:           cfg,
		client:        client,
		now:           time.Now,
		wait:          5 * time.Second,
		evaluateLimit: evaluateTimeout,
	}
}

// Run evaluates the plan of a task and always tries to report. A run that cannot finish is reported as
// failed with fixed text, so a broken evaluation does not read as a pass and no internal error reaches the
// run. A task that does not pass Check makes no request at all.
func (r *Runner) Run(ctx context.Context, task Task) error {
	callback, ok := task.Check(r.cfg.APIHost)
	if !ok {
		return errors.New("the task does not name this API host")
	}
	result, runErr := func() (result taskResult, err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = errors.New("the evaluation panicked")
			}
		}()
		evaluation, cancel := context.WithTimeout(ctx, r.evaluateLimit)
		defer cancel()
		return r.evaluate(evaluation, task)
	}()
	if runErr != nil {
		result = taskResult{status: statusFailed, message: "ipso could not finish this check, so the plan was not evaluated. Run the plan again to retry."}
	}
	if err := r.report(ctx, task, callback, result); err != nil {
		return errors.Join(runErr, err)
	}
	if runErr != nil {
		return fmt.Errorf("the evaluation did not finish: %w", runErr)
	}
	r.cfg.Logger.Info("run task evaluated", "task_result", task.TaskResult, "run", task.Run, "status", result.status,
		"plan_sha256", result.planSHA256, "checks", result.checks, "failed", result.failed)
	return nil
}

func (r *Runner) evaluate(ctx context.Context, task Task) (taskResult, error) {
	if task.Stage != stagePostPlan && task.Stage != stagePreApply {
		return taskResult{status: statusFailed, message: "ipso evaluates a plan, so attach this run task to the post-plan or the pre-apply stage."}, nil
	}
	planURL, ok := parseAPIURL(task.PlanURL, r.cfg.APIHost, validPlanPath)
	if !ok {
		return taskResult{}, errors.New("the plan URL is not on the API host")
	}
	plan, err := r.openPlan(ctx, planURL, task.AccessToken)
	if err != nil {
		return taskResult{}, err
	}
	defer func() { _ = plan.Close() }()
	report, err := r.cfg.Bundle.Evaluate(plan, r.cfg.Env, r.now())
	if err != nil {
		// The text of this error can quote the plan. The code cannot.
		return taskResult{}, fmt.Errorf("the plan could not be evaluated: %s", codeOr(plancheck.Code(err), "no code"))
	}
	return resultOf(report, task.Outcomes), nil
}

func codeOr(code, fallback string) string {
	if code == "" {
		return fallback
	}
	return code
}

// openPlan asks the API for the plan and follows one redirect, without the token, to an allowed host.
// A plan that is not ready answers 204, and it gets a few more tries.
func (r *Runner) openPlan(ctx context.Context, planURL, token string) (io.ReadCloser, error) {
	const attempts = 6
	for attempt := range attempts {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, planURL, nil)
		if err != nil {
			return nil, errors.New("the plan request cannot be built")
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := r.client.Do(request)
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
			if err := sleepContext(ctx, r.wait); err != nil {
				return nil, err
			}
		case http.StatusTemporaryRedirect, http.StatusFound, http.StatusSeeOther:
			location := response.Header.Get("Location")
			_ = response.Body.Close()
			return r.followPlanRedirect(ctx, location)
		default:
			_ = response.Body.Close()
			return nil, fmt.Errorf("the plan request answered %d", response.StatusCode)
		}
	}
	return nil, errors.New("the plan is not ready")
}

func (r *Runner) followPlanRedirect(ctx context.Context, location string) (io.ReadCloser, error) {
	target, err := url.Parse(location)
	if err != nil || target.Scheme != "https" || target.User != nil {
		return nil, errors.New("the plan redirect is not HTTPS")
	}
	if target.Host != r.cfg.APIHost && !slices.Contains(r.cfg.PlanHosts, target.Host) {
		return nil, errors.New("the plan redirect names a host that is not allowed")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, errors.New("the plan download cannot be built")
	}
	response, err := r.client.Do(request)
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
func (r *Runner) report(ctx context.Context, task Task, callback string, result taskResult) error {
	body, err := json.Marshal(result.document())
	if err != nil {
		return errors.New("the result cannot be encoded")
	}
	const attempts = 3
	var last error
	for attempt := range attempts {
		if attempt > 0 {
			if err := sleepContext(ctx, r.wait*time.Duration(attempt)); err != nil {
				return errors.Join(last, err)
			}
		}
		retry, err := r.patch(ctx, callback, task.AccessToken, body)
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

func (r *Runner) patch(ctx context.Context, callback, token string, body []byte) (retry bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPatch, callback, strings.NewReader(string(body)))
	if err != nil {
		return false, errors.New("the callback cannot be built")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", jsonAPI)
	response, err := r.client.Do(request)
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
