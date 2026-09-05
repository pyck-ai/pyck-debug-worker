package probe

import (
	"errors"
	"strings"
	"testing"
	"time"

	namespacepb "go.temporal.io/api/namespace/v1"
	taskqueuepb "go.temporal.io/api/taskqueue/v1"
	"go.temporal.io/api/workflowservice/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	enumspb "go.temporal.io/api/enums/v1"

	"github.com/pyck-ai/pyck-debug-worker/internal/secret"
)

func TestValidateTaskQueue(t *testing.T) {
	tests := []struct {
		name  string
		queue string
		valid bool
	}{
		{name: "the default", queue: "pyck-debug-worker-probe", valid: true},
		{name: "another probe queue", queue: "pyck-debug-worker-canary", valid: true},
		{name: "the prefix alone", queue: "pyck-debug-worker-", valid: true},
		// Everything below would poll a queue real workers depend on.
		{name: "a real queue", queue: "default", valid: false},
		{name: "a production queue", queue: "pyck-workflows", valid: false},
		{name: "prefix without the dash", queue: "pyck-debug-worker", valid: false},
		{name: "prefix in the middle", queue: "x-pyck-debug-worker-probe", valid: false},
		{name: "empty", queue: "", valid: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTaskQueue(tc.queue)
			if tc.valid {
				if err != nil {
					t.Errorf("ValidateTaskQueue(%q) = %v, want nil", tc.queue, err)
				}

				return
			}

			if !errors.Is(err, ErrTaskQueue) {
				t.Errorf("ValidateTaskQueue(%q) = %v, want ErrTaskQueue", tc.queue, err)
			}
		})
	}
}

func TestSystemInfoVerdict(t *testing.T) {
	tests := []struct {
		name     string
		resp     *workflowservice.GetSystemInfoResponse
		err      error
		healthOK bool
		wantOK   bool
		contains string
	}{
		{
			name:     "server version",
			resp:     &workflowservice.GetSystemInfoResponse{ServerVersion: "1.29.0"},
			wantOK:   true,
			contains: "GetSystemInfo server=1.29.0",
		},
		{
			name:     "server without a version string",
			resp:     &workflowservice.GetSystemInfoResponse{},
			wantOK:   true,
			contains: "server=unknown",
		},
		{
			// Old servers do not have the call and still serve workflows.
			name:     "unimplemented is an old server, not a fault",
			err:      status.Error(codes.Unimplemented, "unknown method"),
			wantOK:   true,
			contains: "predates the call",
		},
		{
			name:     "unauthenticated with health up is definitively auth",
			err:      status.Error(codes.Unauthenticated, "bad key"),
			healthOK: true,
			wantOK:   false,
			contains: "definitively auth, not the network",
		},
		{
			// What the live pyck frontend actually returns for a bad key.
			name:     "permission denied with health up is also definitively auth",
			err:      status.Error(codes.PermissionDenied, "unauthorized"),
			healthOK: true,
			wantOK:   false,
			contains: "definitively auth, not the network",
		},
		{
			name:     "permission denied never vouches for the identity",
			err:      status.Error(codes.PermissionDenied, "unauthorized"),
			healthOK: false,
			wantOK:   false,
			contains: "rejected key or wrong scope",
		},
		{
			name:     "unauthenticated with health down stays ambiguous",
			err:      status.Error(codes.Unauthenticated, "bad key"),
			healthOK: false,
			wantOK:   false,
			contains: "unauthenticated: bad API key",
		},
		{
			name:     "unavailable",
			err:      status.Error(codes.Unavailable, "connection refused"),
			wantOK:   false,
			contains: "unavailable:",
		},
		{
			name:     "rate limited",
			err:      status.Error(codes.ResourceExhausted, "slow down"),
			wantOK:   false,
			contains: "rate-limited but healthy",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, detail := systemInfoVerdict(tc.resp, tc.err, tc.healthOK)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v (detail %q)", ok, tc.wantOK, detail)
			}

			if !strings.Contains(detail, tc.contains) {
				t.Errorf("detail %q does not contain %q", detail, tc.contains)
			}

			if strings.Contains(detail, "definitively") && !tc.healthOK {
				t.Errorf("detail %q claims certainty the health stage did not provide", detail)
			}
		})
	}
}

func TestNamespaceVerdict(t *testing.T) {
	registered := &workflowservice.DescribeNamespaceResponse{
		NamespaceInfo: &namespacepb.NamespaceInfo{
			Name:  "default",
			State: enumspb.NAMESPACE_STATE_REGISTERED,
		},
	}

	tests := []struct {
		name     string
		resp     *workflowservice.DescribeNamespaceResponse
		err      error
		wantOK   bool
		contains string
		absent   string
	}{
		{name: "registered", resp: registered, wantOK: true, contains: "default Registered"},
		{
			// The credential was accepted; the name is simply wrong.
			name:     "not found is a typo, not an auth fault",
			err:      status.Error(codes.NotFound, "namespace not found"),
			wantOK:   false,
			contains: "a typo, not an auth fault",
			absent:   "API key",
		},
		{
			name:     "permission denied does not claim the identity is valid",
			err:      status.Error(codes.PermissionDenied, "nope"),
			wantOK:   false,
			contains: "rejected key or wrong scope",
		},
		{
			name:     "unauthenticated is the key",
			err:      status.Error(codes.Unauthenticated, "nope"),
			wantOK:   false,
			contains: "bad API key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, detail := namespaceVerdict(tc.resp, tc.err)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v (detail %q)", ok, tc.wantOK, detail)
			}

			if !strings.Contains(detail, tc.contains) {
				t.Errorf("detail %q does not contain %q", detail, tc.contains)
			}

			if tc.absent != "" && strings.Contains(detail, tc.absent) {
				t.Errorf("detail %q blames %q", detail, tc.absent)
			}
		})
	}
}

func TestEffectiveNamespace(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want string
	}{
		{name: "nothing set falls back to the sdk default", want: defaultNamespace},
		{
			name: "environment",
			opts: Options{TemporalNamespace: "from-env"},
			want: "from-env",
		},
		{
			name: "flag wins",
			opts: Options{TemporalNamespace: "from-env", NamespaceFlag: "from-flag"},
			want: "from-flag",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveNamespace(tc.opts); got != tc.want {
				t.Errorf("effectiveNamespace() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTemporalStagesGate(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want bool
	}{
		{name: "no credential, no stages", opts: Options{}, want: false},
		{
			name: "insecure is the credential-free in-cluster path",
			opts: Options{Insecure: true},
			want: true,
		},
		{
			name: "an api key opens the gate",
			opts: Options{APIKey: secret.New("k")},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gated := tc.opts.APIKey.IsZero() && !tc.opts.Insecure
			if gated == tc.want {
				t.Errorf("gate open = %v, want %v", !gated, tc.want)
			}

			if !tc.want {
				if got := temporalStages(t.Context(), testTarget, tc.opts, true); got != nil {
					t.Errorf("got %d results, want none without a credential", len(got))
				}
			}
		})
	}
}

// pollerAt builds a DescribeTaskQueue response holding one poll of the given
// age.
func pollerAt(identity string, now time.Time, age time.Duration) *workflowservice.DescribeTaskQueueResponse {
	return &workflowservice.DescribeTaskQueueResponse{
		Pollers: []*taskqueuepb.PollerInfo{{
			Identity:       identity,
			LastAccessTime: timestamppb.New(now.Add(-age)),
		}},
	}
}

func TestPollerObserve(t *testing.T) {
	const identity = "pyck-debug-worker@host@1"

	t.Run("reports the longest held poll", func(t *testing.T) {
		p := &poller{identity: identity, logger: &sdkLogger{}}
		now := time.Now()

		resp := &workflowservice.DescribeTaskQueueResponse{
			Pollers: []*taskqueuepb.PollerInfo{
				{Identity: identity, LastAccessTime: timestamppb.New(now.Add(-5 * time.Second))},
				{Identity: identity, LastAccessTime: timestamppb.New(now.Add(-42 * time.Second))},
				{Identity: "someone-else", LastAccessTime: timestamppb.New(now.Add(-90 * time.Second))},
			},
		}

		held, found := p.observe(resp, now)
		if !found {
			t.Fatal("found = false, want true")
		}

		if held.Round(time.Second) != 42*time.Second {
			t.Errorf("held = %s, want 42s", held)
		}
	})

	t.Run("absent identity", func(t *testing.T) {
		p := &poller{identity: identity, logger: &sdkLogger{}}
		now := time.Now()

		if _, found := p.observe(pollerAt("another-worker", now, time.Second), now); found {
			t.Error("found = true for someone else's poller")
		}
	})

	t.Run("a poll that ended early is a truncation", func(t *testing.T) {
		p := &poller{identity: identity, logger: &sdkLogger{}}
		now := time.Now()

		// Held 10s, then 30s later a fresh poll: the old one lasted at most
		// 40s, well inside the 60s long poll, so it was cut short.
		p.observe(pollerAt(identity, now, 10*time.Second), now)
		p.observe(pollerAt(identity, now.Add(30*time.Second), 2*time.Second), now.Add(30*time.Second))

		if p.truncations != 1 {
			t.Errorf("truncations = %d, want 1", p.truncations)
		}
	})

	t.Run("a poll that reached the long poll boundary is not a truncation", func(t *testing.T) {
		p := &poller{identity: identity, logger: &sdkLogger{}}
		now := time.Now()

		// Held 45s, seen again 30s later: the poll could have run to 75s, so
		// its end cannot be attributed to a truncation.
		p.observe(pollerAt(identity, now, 45*time.Second), now)
		p.observe(pollerAt(identity, now.Add(30*time.Second), time.Second), now.Add(30*time.Second))

		if p.truncations != 0 {
			t.Errorf("truncations = %d, want 0: an uncertain end must not be counted", p.truncations)
		}
	})

	t.Run("a poll that keeps being held is not a truncation", func(t *testing.T) {
		p := &poller{identity: identity, logger: &sdkLogger{}}
		now := time.Now()

		p.observe(pollerAt(identity, now, 10*time.Second), now)
		p.observe(pollerAt(identity, now.Add(30*time.Second), 40*time.Second), now.Add(30*time.Second))

		if p.truncations != 0 {
			t.Errorf("truncations = %d, want 0", p.truncations)
		}
	})
}

func TestPollerGraceOnlyCoversStartup(t *testing.T) {
	// The server needs one round trip to learn about a poller, so the cycle
	// that starts the worker must not report it missing. A worker that is
	// still absent later is a genuine failure.
	tests := []struct {
		name string
		up   time.Duration
		want bool
	}{
		{name: "just started", up: 100 * time.Millisecond, want: true},
		{name: "inside the grace", up: pollerGrace - time.Second, want: true},
		{name: "past the grace", up: pollerGrace + time.Second, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := time.Since(time.Now().Add(-tc.up)) < pollerGrace; got != tc.want {
				t.Errorf("within grace = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPollerDetail(t *testing.T) {
	p := &poller{
		identity: "id",
		queue:    "pyck-debug-worker-probe",
		started:  time.Now().Add(-90 * time.Second),
		logger:   &sdkLogger{},
	}

	got := p.detail(12*time.Second, false)
	if !strings.HasPrefix(got, "poller up 1m30s  held 12s  truncations=0") {
		t.Errorf("detail = %q", got)
	}

	// A drained connection is expected during a rollout and must never be a
	// failure, only a note.
	p.logger.Warn("Failed to poll for task", "Error", "http2: server sent GOAWAY and closed the connection")

	got = p.detail(0, true)
	if !strings.Contains(got, "held ?") || !strings.Contains(got, "goaway=1") {
		t.Errorf("detail = %q", got)
	}
}

func TestSDKLoggerOnlyCountsGoaway(t *testing.T) {
	l := &sdkLogger{}

	l.Info("worker started", "TaskQueue", "pyck-debug-worker-probe")
	l.Debug("poll succeeded")
	l.Error("some other failure", "Error", "connection refused")

	if got := l.goaways(); got != 0 {
		t.Errorf("goaways = %d, want 0", got)
	}

	l.Warn("Failed to poll", "Error", "http2: server sent GOAWAY")
	l.Error("stream terminated", "Error", "received goaway")

	if got := l.goaways(); got != 2 {
		t.Errorf("goaways = %d, want 2", got)
	}
}

func TestIsGoaway(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "upper", err: errors.New("http2: server sent GOAWAY"), want: true},
		{name: "lower", err: errors.New("received goaway and closed"), want: true},
		{name: "unrelated", err: errors.New("connection refused"), want: false},
		{
			name: "wrapped in a status",
			err:  status.Error(codes.Unavailable, "transport: http2: server sent GOAWAY"),
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isGoaway(tc.err); got != tc.want {
				t.Errorf("isGoaway() = %v, want %v", got, tc.want)
			}
		})
	}
}
