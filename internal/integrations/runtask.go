package integrations

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/runtask"
)

// RunTaskConfig is what the run task service needs.
type RunTaskConfig struct {
	HMACKey []byte
	Bundle  runtask.PlanEvaluator
	// Env limits the checks to one environment, as --env does. Empty evaluates every plan check in force.
	Env string
	// APIHost is the only host that receives the run's access token. Empty means runtask.DefaultHCPHost.
	APIHost string
	// PlanHosts are the hosts a plan download may redirect to, besides APIHost. No token goes there.
	// Nil means runtask.DefaultPlanHost.
	PlanHosts []string
	Logger    *slog.Logger
}

// taskRunner is *runtask.Runner. Tests replace it.
type taskRunner interface {
	Run(ctx context.Context, task runtask.Task) error
}

// RunTaskService verifies run task requests and answers them on a bounded queue (ADR-0065). It runs the
// receiver and the runner of package runtask in one process. The BYOC data plane runs them apart (ADR-0144).
type RunTaskService struct {
	cfg    RunTaskConfig
	jobs   *Service
	runner taskRunner
}

// NewRunTaskService returns a service. Run its workers with Run before serving Handler.
func NewRunTaskService(cfg RunTaskConfig) *RunTaskService {
	return &RunTaskService{
		cfg:  cfg,
		jobs: &Service{cfg: Config{Logger: cfg.Logger}, queue: make(chan job, queueSize), seen: newDeliverySet(seenDeliveries), timeout: runtask.JobTimeout},
		runner: runtask.NewRunner(runtask.RunnerConfig{
			Bundle:    cfg.Bundle,
			Env:       cfg.Env,
			APIHost:   cfg.APIHost,
			PlanHosts: cfg.PlanHosts,
			Logger:    cfg.Logger,
		}),
	}
}

// Run works the queue until ctx ends.
func (s *RunTaskService) Run(ctx context.Context) { s.jobs.Run(ctx) }

// Handler serves POST runtask.Path.
func (s *RunTaskService) Handler() http.Handler {
	return runtask.NewHandler(runtask.ReceiverConfig{HMACKey: s.cfg.HMACKey, APIHost: s.cfg.APIHost, Logger: s.cfg.Logger}, s.accept)
}

// accept queues the task. A task whose result id was already taken is not queued again, and is answered as
// taken. A full queue forgets the id and answers busy.
func (s *RunTaskService) accept(task runtask.Task) bool {
	if !s.jobs.seen.add(task.TaskResult) {
		return true
	}
	next := job{delivery: task.TaskResult, name: "run task", run: func(ctx context.Context, _ uuid.UUID) error {
		return s.runner.Run(ctx, task)
	}}
	select {
	case s.jobs.queue <- next:
		return true
	default:
		// HCP Terraform triggers the task again.
		s.jobs.seen.forget(task.TaskResult)
		return false
	}
}
