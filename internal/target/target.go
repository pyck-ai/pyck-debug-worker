// Package target turns an --env name or an explicit --target argument into the
// concrete host:port endpoints the prober is allowed to touch.
package target

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Kind is the protocol spoken to a target.
type Kind string

const (
	// KindGRPC is a gRPC endpoint (Temporal frontend).
	KindGRPC Kind = "grpc"
	// KindHTTPS is an HTTP/2-over-TLS endpoint (app / gateway domain).
	KindHTTPS Kind = "https"
)

// Errors returned by this package.
var (
	// ErrUnknownEnv is returned by Resolve for an env name that has no domain.
	ErrUnknownEnv = errors.New("unknown env")
	// ErrBadTarget is returned by ParseTarget for a malformed --target value.
	ErrBadTarget = errors.New("bad target")
)

// Target is one resolved endpoint.
type Target struct {
	Host string
	Port int
	Kind Kind
}

// Addr renders the target as host:port.
func (t Target) Addr() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// String renders the target as host:port.
func (t Target) String() string {
	return t.Addr()
}

// defaultPort is the port used for every env-derived target. In-cluster
// endpoints on other ports must be named explicitly with --target.
const defaultPort = 443

// featurePrefix is the --env prefix selecting a feature environment.
const featurePrefix = "feature/"

// domains maps an --env name to its DNS domain. Two traps live in this table:
// prod's domain is eu, not prod, and feature envs (handled in Resolve) join the
// branch with "-" rather than ".".
var domains = map[string]string{
	"local": "local-test.pyck.cloud",
	"dev":   "dev.pyck.cloud",
	"test":  "test.pyck.cloud",
	"demo":  "demo.pyck.cloud",
	"prod":  "eu.pyck.cloud",
}

// Resolve returns the default target set for an env: the Temporal frontend
// followed by the app/gateway domain. Anything else must be named explicitly
// with --target.
func Resolve(env string) ([]Target, error) {
	if branch, ok := strings.CutPrefix(env, featurePrefix); ok {
		if branch == "" {
			return nil, fmt.Errorf("%w: %q has no branch", ErrUnknownEnv, env)
		}

		return []Target{
			{Host: "wf-" + branch + ".feature.pyck.cloud", Port: defaultPort, Kind: KindGRPC},
			{Host: branch + ".feature.pyck.cloud", Port: defaultPort, Kind: KindHTTPS},
		}, nil
	}

	domain, ok := domains[env]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownEnv, env)
	}

	return []Target{
		{Host: "wf." + domain, Port: defaultPort, Kind: KindGRPC},
		{Host: domain, Port: defaultPort, Kind: KindHTTPS},
	}, nil
}

// ParseTarget parses the --target form host:port[=grpc|https]. The kind
// defaults to https when omitted.
func ParseTarget(s string) (Target, error) {
	hostPort, kindText, hasKind := strings.Cut(s, "=")

	kind := KindHTTPS
	if hasKind {
		switch Kind(kindText) {
		case KindGRPC:
			kind = KindGRPC
		case KindHTTPS:
			kind = KindHTTPS
		default:
			return Target{}, fmt.Errorf("%w: %q: kind must be grpc or https", ErrBadTarget, s)
		}
	}

	host, portText, err := net.SplitHostPort(hostPort)
	if err != nil {
		return Target{}, fmt.Errorf("%w: %q: want host:port[=grpc|https]", ErrBadTarget, s)
	}

	if host == "" {
		return Target{}, fmt.Errorf("%w: %q: empty host", ErrBadTarget, s)
	}

	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return Target{}, fmt.Errorf("%w: %q: port out of range", ErrBadTarget, s)
	}

	return Target{Host: host, Port: port, Kind: kind}, nil
}

// Denied reports whether a host/path is on the hardcoded denylist, together
// with the reason. A 30s prober against these endpoints causes real damage.
func Denied(host, path string) (bool, string) {
	name, _, _ := strings.Cut(strings.ToLower(host), ":")

	switch {
	case strings.HasPrefix(name, "otel.") || strings.HasPrefix(name, "otel-grpc."):
		return true, "OTLP write path"
	case strings.HasPrefix(name, "storage.") || strings.HasPrefix(name, "remote-ui-"):
		return true, "billable Hetzner S3 egress"
	case strings.HasPrefix(name, "boxes-nonprod."):
		return true, "may spawn sandboxes"
	}

	route, _, _ := strings.Cut(strings.ToLower(path), "?")

	switch {
	case route == "/ws" || strings.HasPrefix(route, "/ws/"):
		return true, "NATS websocket — leaks server-side conns"
	case strings.Contains(route, "log-follow"):
		return true, "worker-api log-follow is a long-lived stream"
	}

	return false, ""
}
