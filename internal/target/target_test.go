package target

import (
	"errors"
	"testing"
)

func TestResolve(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want []Target
	}{
		{
			name: "local",
			env:  "local",
			want: []Target{
				{Host: "wf.local-test.pyck.cloud", Port: 443, Kind: KindGRPC},
				{Host: "local-test.pyck.cloud", Port: 443, Kind: KindHTTPS},
			},
		},
		{
			name: "dev",
			env:  "dev",
			want: []Target{
				{Host: "wf.dev.pyck.cloud", Port: 443, Kind: KindGRPC},
				{Host: "dev.pyck.cloud", Port: 443, Kind: KindHTTPS},
			},
		},
		{
			name: "test",
			env:  "test",
			want: []Target{
				{Host: "wf.test.pyck.cloud", Port: 443, Kind: KindGRPC},
				{Host: "test.pyck.cloud", Port: 443, Kind: KindHTTPS},
			},
		},
		{
			name: "demo",
			env:  "demo",
			want: []Target{
				{Host: "wf.demo.pyck.cloud", Port: 443, Kind: KindGRPC},
				{Host: "demo.pyck.cloud", Port: 443, Kind: KindHTTPS},
			},
		},
		{
			// Trap: prod's domain is eu, never prod.
			name: "prod maps to the eu domain",
			env:  "prod",
			want: []Target{
				{Host: "wf.eu.pyck.cloud", Port: 443, Kind: KindGRPC},
				{Host: "eu.pyck.cloud", Port: 443, Kind: KindHTTPS},
			},
		},
		{
			// Trap: feature envs join the branch with "-", not ".".
			name: "feature branch uses a dash separator",
			env:  "feature/my-branch",
			want: []Target{
				{Host: "wf-my-branch.feature.pyck.cloud", Port: 443, Kind: KindGRPC},
				{Host: "my-branch.feature.pyck.cloud", Port: 443, Kind: KindHTTPS},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Resolve(tc.env)
			if err != nil {
				t.Fatalf("Resolve(%q) error: %v", tc.env, err)
			}

			if len(got) != len(tc.want) {
				t.Fatalf("Resolve(%q) = %v, want %v", tc.env, got, tc.want)
			}

			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("Resolve(%q)[%d] = %+v, want %+v", tc.env, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestResolveProdIsNotProdDotPyckCloud(t *testing.T) {
	got, err := Resolve("prod")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	for _, tgt := range got {
		if tgt.Host == "prod.pyck.cloud" || tgt.Host == "wf.prod.pyck.cloud" {
			t.Fatalf("prod resolved to %q, want the eu domain", tgt.Host)
		}
	}
}

func TestResolveUnknownEnv(t *testing.T) {
	tests := []string{"", "prd", "production", "feature/", "eu"}

	for _, env := range tests {
		t.Run(env, func(t *testing.T) {
			if _, err := Resolve(env); !errors.Is(err, ErrUnknownEnv) {
				t.Errorf("Resolve(%q) error = %v, want ErrUnknownEnv", env, err)
			}
		})
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Target
	}{
		{
			name: "defaults to https",
			in:   "test.pyck.cloud:443",
			want: Target{Host: "test.pyck.cloud", Port: 443, Kind: KindHTTPS},
		},
		{
			name: "explicit https",
			in:   "test.pyck.cloud:443=https",
			want: Target{Host: "test.pyck.cloud", Port: 443, Kind: KindHTTPS},
		},
		{
			name: "in-cluster grpc",
			in:   "pyck-temporal-internal-frontend:7236=grpc",
			want: Target{Host: "pyck-temporal-internal-frontend", Port: 7236, Kind: KindGRPC},
		},
		{
			name: "ipv6 literal",
			in:   "[::1]:7233=grpc",
			want: Target{Host: "::1", Port: 7233, Kind: KindGRPC},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTarget(tc.in)
			if err != nil {
				t.Fatalf("ParseTarget(%q) error: %v", tc.in, err)
			}

			if got != tc.want {
				t.Errorf("ParseTarget(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseTargetErrors(t *testing.T) {
	tests := []string{
		"test.pyck.cloud",
		"test.pyck.cloud:443=http",
		"test.pyck.cloud:0",
		"test.pyck.cloud:70000",
		"test.pyck.cloud:https",
		":443",
		"",
	}

	for _, in := range tests {
		t.Run(in, func(t *testing.T) {
			if _, err := ParseTarget(in); !errors.Is(err, ErrBadTarget) {
				t.Errorf("ParseTarget(%q) error = %v, want ErrBadTarget", in, err)
			}
		})
	}
}

func TestTargetAddr(t *testing.T) {
	tgt := Target{Host: "wf.test.pyck.cloud", Port: 443, Kind: KindGRPC}
	if got, want := tgt.Addr(), "wf.test.pyck.cloud:443"; got != want {
		t.Errorf("Addr() = %q, want %q", got, want)
	}

	if got, want := tgt.String(), "wf.test.pyck.cloud:443"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	v6 := Target{Host: "::1", Port: 7233, Kind: KindGRPC}
	if got, want := v6.Addr(), "[::1]:7233"; got != want {
		t.Errorf("Addr() = %q, want %q", got, want)
	}
}

func TestDenied(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		path   string
		want   bool
		reason string
	}{
		{
			name: "otel", host: "otel.test.pyck.cloud", path: "/",
			want: true, reason: "OTLP write path",
		},
		{
			name: "otel-grpc", host: "otel-grpc.test.pyck.cloud", path: "/",
			want: true, reason: "OTLP write path",
		},
		{
			name: "nats websocket", host: "test.pyck.cloud", path: "/ws",
			want: true, reason: "NATS websocket — leaks server-side conns",
		},
		{
			name: "nats websocket subpath", host: "test.pyck.cloud", path: "/ws/foo",
			want: true, reason: "NATS websocket — leaks server-side conns",
		},
		{
			name: "storage", host: "storage.test.pyck.cloud", path: "/",
			want: true, reason: "billable Hetzner S3 egress",
		},
		{
			name: "remote ui", host: "remote-ui-abc.test.pyck.cloud", path: "/",
			want: true, reason: "billable Hetzner S3 egress",
		},
		{
			name: "boxes nonprod", host: "boxes-nonprod.pyck.cloud", path: "/",
			want: true, reason: "may spawn sandboxes",
		},
		{
			name: "worker-api log follow", host: "worker-api.test.pyck.cloud", path: "/v1/log-follow",
			want: true, reason: "worker-api log-follow is a long-lived stream",
		},
		{
			name: "host is matched case-insensitively", host: "OTEL.test.pyck.cloud", path: "/",
			want: true, reason: "OTLP write path",
		},
		{
			name: "host with port", host: "otel.test.pyck.cloud:443", path: "/",
			want: true, reason: "OTLP write path",
		},
		{
			name: "allowed settings", host: "test.pyck.cloud", path: "/static/settings.json",
			want: false,
		},
		{
			name: "allowed oidc discovery", host: "auth.test.pyck.cloud",
			path: "/.well-known/openid-configuration", want: false,
		},
		{
			name: "allowed healthz", host: "worker-api.test.pyck.cloud", path: "/healthz",
			want: false,
		},
		{
			name: "websocket-ish path is not /ws", host: "test.pyck.cloud", path: "/wsx",
			want: false,
		},
		{
			name: "temporal frontend", host: "wf.test.pyck.cloud", path: "",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := Denied(tc.host, tc.path)
			if got != tc.want {
				t.Fatalf("Denied(%q, %q) = %v, want %v", tc.host, tc.path, got, tc.want)
			}

			if got && reason != tc.reason {
				t.Errorf("Denied(%q, %q) reason = %q, want %q", tc.host, tc.path, reason, tc.reason)
			}

			if !got && reason != "" {
				t.Errorf("Denied(%q, %q) reason = %q, want empty", tc.host, tc.path, reason)
			}
		})
	}
}
