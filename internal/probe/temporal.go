package probe

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/grpc/codes"

	"github.com/pyck-ai/pyck-debug-worker/internal/report"
	"github.com/pyck-ai/pyck-debug-worker/internal/target"
)

// TaskQueuePrefix is the only namespace of task queue names this binary is
// allowed to poll.
//
// Polling a real queue would make the prober steal live workflow tasks, which
// is the one hazard the host/path denylist cannot express. A typo in
// --task-queue must therefore be fatal at startup, not discovered in
// production.
const TaskQueuePrefix = "pyck-debug-worker-"

// defaultNamespace matches the SDK's own default, so the namespace this tool
// reports is the namespace it actually used.
const defaultNamespace = "default"

// pollerGrace is how long after startup the server is allowed not to know
// about our poller yet. The first poll needs one round trip to register, so
// without this the cycle that starts the worker always reports it missing.
const pollerGrace = 15 * time.Second

// longPollDuration is Temporal's long-poll timeout. A poll that ends earlier
// than this was cut short by something in between — which is the entire point
// of the longpoll stage.
const longPollDuration = 60 * time.Second

// effectiveNamespace resolves which namespace the Temporal stages address:
// the flag, then the environment, then the SDK's own default so the reported
// namespace is the one actually used.
func effectiveNamespace(opts Options) string {
	switch {
	case opts.NamespaceFlag != "":
		return opts.NamespaceFlag
	case opts.TemporalNamespace != "":
		return opts.TemporalNamespace
	default:
		return defaultNamespace
	}
}

// ErrTaskQueue is returned for a task queue name outside TaskQueuePrefix.
var ErrTaskQueue = errors.New("task queue")

// ValidateTaskQueue rejects any queue this binary must not poll.
func ValidateTaskQueue(name string) error {
	if !strings.HasPrefix(name, TaskQueuePrefix) {
		return fmt.Errorf(
			"%w: %q must start with %q: polling a real queue would steal live workflow tasks",
			ErrTaskQueue, name, TaskQueuePrefix)
	}

	return nil
}

// temporalStages runs the Temporal half of the ladder.
//
// The gate is a credential: an API key, or --insecure for the plaintext
// in-cluster path which has no credentials at all. Without either there is
// nothing to authenticate with and the stages print nothing.
//
// healthOK is carried in from the health stage because the two together are
// decisive: Temporal deployments routinely exempt the health endpoint from
// authentication, so health answering while GetSystemInfo returns
// Unauthenticated pins the fault on the credential rather than the network.
func temporalStages(ctx context.Context, tgt target.Target, opts Options, healthOK bool) []report.Result {
	if opts.APIKey.IsZero() && !opts.Insecure {
		return nil
	}

	namespace := effectiveNamespace(opts)

	temporal, err := opts.Clients.temporalClient(tgt, opts, namespace)
	if err != nil {
		return []report.Result{
			stage(tgt, "temporal", func() (bool, string) {
				return false, "client rejected the configuration: " + classify(err)
			}),
		}
	}

	results := []report.Result{
		stage(tgt, "temporal", func() (bool, string) {
			resp, err := temporal.systemInfo(ctx)

			return systemInfoVerdict(resp, err, healthOK)
		}),
		stage(tgt, "namespace", func() (bool, string) {
			resp, err := temporal.describeNamespace(ctx, namespace)

			return namespaceVerdict(resp, err)
		}),
	}

	if !opts.Deep {
		return results
	}

	return append(results, longpollStage(ctx, tgt, opts))
}

// systemInfoVerdict judges GetSystemInfo.
//
// The call goes through WorkflowService() rather than a client helper: it
// bypasses the SDK's internal retries, so the measured duration is one round
// trip rather than a retry storm.
func systemInfoVerdict(resp *workflowservice.GetSystemInfoResponse, err error, healthOK bool) (bool, string) {
	if err == nil {
		version := resp.GetServerVersion()
		if version == "" {
			version = "unknown"
		}

		return true, "GetSystemInfo server=" + version
	}

	code, _ := codeOf(err)

	switch code {
	case codes.Unimplemented:
		// Servers older than the call still serve workflows.
		return true, "GetSystemInfo unimplemented: server predates the call"
	case codes.Unauthenticated, codes.PermissionDenied:
		// Temporal deployments routinely exempt the health endpoint from
		// authentication. Health answering while this call is rejected is
		// therefore decisive: the credential is the fault, not the path to
		// the server.
		//
		// Observed 2026-09-04: the pyck frontend answers PermissionDenied,
		// not Unauthenticated, for an outright invalid key — so neither code
		// may claim the identity is valid.
		detail := grpcReasonOr(err)
		if healthOK {
			detail += " — health answered, so this is definitively auth, not the network"
		}

		return false, detail
	default:
		return false, classify(err)
	}
}

// namespaceVerdict judges DescribeNamespace. It is the cheapest call that
// proves both that the namespace exists and that the credential is scoped to
// it.
func namespaceVerdict(resp *workflowservice.DescribeNamespaceResponse, err error) (bool, string) {
	if err == nil {
		info := resp.GetNamespaceInfo()

		return true, info.GetName() + " " + info.GetState().String()
	}

	code, _ := codeOf(err)

	switch code {
	case codes.NotFound:
		// Not an auth problem: the credential was accepted and the server
		// simply has no such namespace.
		return false, "namespace not found: a typo, not an auth fault"
	case codes.PermissionDenied:
		return false, "permission denied: the key is not authorised for this namespace " +
			"(rejected key or wrong scope)"
	default:
		return false, classify(err)
	}
}

// longpollStage reports on the worker's long poll.
//
// It is the only test of Traefik's readTimeout, an unmodified upstream default
// of 60s that nobody chose and that lands exactly on Temporal's 60s long poll.
// A poll that keeps ending early is that timeout truncating it.
//
// A mid-poll GOAWAY is expected rather than exceptional — Traefik runs 3-6
// replicas with a 15s preStop, so every rollout drops long-lived h2 streams.
// It is reported, never failed.
func longpollStage(ctx context.Context, tgt target.Target, opts Options) report.Result {
	return stage(tgt, "longpoll", func() (bool, string) {
		poller, err := opts.Clients.poller(tgt, opts)
		if err != nil {
			return false, "worker did not start: " + classify(err)
		}

		resp, err := poller.describe(ctx)
		if err != nil {
			if isGoaway(err) {
				return true, poller.detail(0, true) + " (describe hit a GOAWAY)"
			}

			return false, classify(err)
		}

		held, found := poller.observe(resp, time.Now())
		if !found {
			if up := time.Since(poller.started); up < pollerGrace {
				return true, fmt.Sprintf("poller registering (worker up %s)", up.Round(time.Second))
			}

			return false, "our poller is absent from " + poller.queue +
				": identity " + poller.identity
		}

		return true, poller.detail(held, false)
	})
}

// isGoaway reports whether the error is an h2 connection being drained.
func isGoaway(err error) bool {
	if err == nil {
		return false
	}

	return strings.Contains(strings.ToUpper(err.Error()), "GOAWAY")
}

// taskQueueType is the queue this prober polls. Only workflow tasks are
// polled; nothing is ever executed.
const taskQueueType = enumspb.TASK_QUEUE_TYPE_WORKFLOW

// temporalClient is the Temporal SDK client plus the raw service handle.
type temporalClient struct {
	client client.Client
}

// systemInfo asks the frontend what it is.
//
// WorkflowService() is used directly: the SDK's own helpers wrap calls in
// automatic retries, which would turn one timing measurement into an average
// over a retry storm.
func (t *temporalClient) systemInfo(ctx context.Context) (*workflowservice.GetSystemInfoResponse, error) {
	callCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	return t.client.WorkflowService().GetSystemInfo(callCtx, &workflowservice.GetSystemInfoRequest{})
}

// describeNamespace proves the namespace exists and that the credential
// reaches it.
func (t *temporalClient) describeNamespace(ctx context.Context, namespace string) (*workflowservice.DescribeNamespaceResponse, error) {
	callCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	return t.client.WorkflowService().DescribeNamespace(callCtx, &workflowservice.DescribeNamespaceRequest{
		Namespace: namespace,
	})
}

// probeWorkflow exists only so the worker has something registered and
// therefore validates on Start. It is never executed: the prober polls its own
// queue, which no client ever submits work to.
func probeWorkflow(workflow.Context) error {
	return nil
}

// poller is the single long-poll worker, started once and observed every cycle.
type poller struct {
	client   client.Client
	worker   worker.Worker
	logger   *sdkLogger
	identity string
	queue    string
	started  time.Time

	mu          sync.Mutex
	lastHeld    time.Duration
	lastSeen    time.Time
	truncations int
}

// describe asks the server which pollers it can see on our queue.
func (p *poller) describe(ctx context.Context) (*workflowservice.DescribeTaskQueueResponse, error) {
	callCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	return p.client.DescribeTaskQueue(callCtx, p.queue, taskQueueType)
}

// observe records how long our longest-held poll has been open and counts the
// polls that ended early.
//
// A truncation is only counted when it is certain: the poll seen at the last
// observation has been replaced, and even granting it the whole gap between
// observations it cannot have reached Temporal's 60s long poll. Anything less
// certain is not counted, because a prober that cries wolf about the network
// is worse than one that stays quiet.
func (p *poller) observe(resp *workflowservice.DescribeTaskQueueResponse, now time.Time) (time.Duration, bool) {
	var (
		held  time.Duration
		found bool
	)

	for _, info := range resp.GetPollers() {
		if info.GetIdentity() != p.identity {
			continue
		}

		found = true

		if age := now.Sub(info.GetLastAccessTime().AsTime()); age > held {
			held = age
		}
	}

	if !found {
		return 0, false
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.lastSeen.IsZero() && held < p.lastHeld {
		if p.lastHeld+now.Sub(p.lastSeen) < longPollDuration {
			p.truncations++
		}
	}

	p.lastHeld = held
	p.lastSeen = now

	return held, true
}

// detail renders the longpoll stage detail.
func (p *poller) detail(held time.Duration, heldUnknown bool) string {
	p.mu.Lock()
	truncations := p.truncations
	p.mu.Unlock()

	heldText := "?"
	if !heldUnknown {
		heldText = held.Round(time.Second).String()
	}

	detail := fmt.Sprintf("poller up %s  held %s  truncations=%d",
		time.Since(p.started).Round(time.Second), heldText, truncations)

	if count := p.logger.goaways(); count > 0 {
		detail += fmt.Sprintf("  goaway=%d (expected on a Traefik rollout)", count)
	}

	return detail
}

// stop drains the worker.
func (p *poller) stop() {
	p.worker.Stop()
}

// sdkLogger keeps the SDK's own logging out of the fixed-width output while
// counting the one message that matters: an h2 connection being drained
// mid-poll.
type sdkLogger struct {
	mu    sync.Mutex
	count int
}

// Debug implements log.Logger.
func (l *sdkLogger) Debug(msg string, keyvals ...any) { l.record(msg, keyvals...) }

// Info implements log.Logger.
func (l *sdkLogger) Info(msg string, keyvals ...any) { l.record(msg, keyvals...) }

// Warn implements log.Logger.
func (l *sdkLogger) Warn(msg string, keyvals ...any) { l.record(msg, keyvals...) }

// Error implements log.Logger.
func (l *sdkLogger) Error(msg string, keyvals ...any) { l.record(msg, keyvals...) }

// record counts GOAWAYs and discards everything else.
func (l *sdkLogger) record(msg string, keyvals ...any) {
	line := msg

	for _, kv := range keyvals {
		line += " " + fmt.Sprint(kv)
	}

	if !strings.Contains(strings.ToUpper(line), "GOAWAY") {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.count++
}

// goaways returns how many drained connections have been seen.
func (l *sdkLogger) goaways() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.count
}

// grpcReasonOr renders the taxonomy verdict for an error, falling back to the
// generic classifier.
func grpcReasonOr(err error) string {
	if reason, ok := grpcReason(err); ok {
		return reason
	}

	return classify(err)
}
