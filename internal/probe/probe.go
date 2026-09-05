// Package probe runs the probe ladder against one target. Each stage consumes
// the previous stage's artifact, so a failure is attributable to a layer
// instead of being reverse-engineered out of a single http.Get.
//
// Stages implemented here are dns, tcp, tls, cert and chain. A stage whose gate
// is not satisfied produces no Result at all.
package probe

import (
	"context"
	"crypto/x509"
	"net"
	"time"

	"github.com/pyck-ai/pyck-debug-worker/internal/report"
	"github.com/pyck-ai/pyck-debug-worker/internal/secret"
	"github.com/pyck-ai/pyck-debug-worker/internal/target"
)

// Options gates the ladder.
type Options struct {
	// Insecure selects plaintext, in-cluster mode: the tls, cert and chain
	// stages do not apply and therefore do not run.
	Insecure bool
	// DebugDNS notes that GODEBUG=netdns=go+1 is in effect.
	DebugDNS bool
	// Roots is the trust anchor set for chain verification and for the TLS
	// configuration of the http2 and grpc stages. Nil means the system pool.
	Roots *x509.CertPool
	// Clients holds the connections reused across cycles. main owns it and it
	// must not be nil.
	Clients *Clients
	// Token is the pyck credential. A zero Secret means no credential was
	// supplied, which gates the auth and tenant stages off entirely.
	Token secret.Secret
	// GatewayURL overrides the GraphQL endpoint (PYCK_GATEWAY_URL).
	GatewayURL string
	// ExpectedTenantID is PYCK_API_TENANT_ID: an input to check against, never
	// a source of truth.
	ExpectedTenantID string
	// TemporalNamespace is TEMPORAL_NAMESPACE, which at pyck is the tenant uuid.
	TemporalNamespace string
	// APIKey is TEMPORAL_API_KEY. A zero Secret gates the Temporal stages off
	// unless Insecure selects the credential-free in-cluster path.
	APIKey secret.Secret
	// NamespaceFlag is --namespace. It takes precedence over
	// TemporalNamespace for the Temporal stages, and is cross-checked under
	// its own label so a flag value is never reported as an env var.
	NamespaceFlag string
	// Deep enables the longpoll stage.
	Deep bool
	// TaskQueue is the queue the long-poll worker uses. It is validated
	// against TaskQueuePrefix at startup.
	TaskQueue string
}

// Run probes one target and returns one Result per stage that ran.
func Run(ctx context.Context, tgt target.Target, opts Options) []report.Result {
	addrs, results := dnsStage(ctx, tgt, opts)

	conn, tcpResults := tcpStage(ctx, tgt, addrs)
	results = append(results, tcpResults...)

	if conn == nil {
		return results
	}

	defer conn.Close()

	if opts.Insecure {
		if tgt.Kind == target.KindGRPC {
			results = append(results, grpcStages(ctx, tgt, opts)...)
		}

		return results
	}

	state, tlsResult := tlsStage(ctx, tgt, conn)
	results = append(results, tlsResult)

	if state == nil {
		return results
	}

	results = append(results,
		certStage(tgt, *state),
		chainStage(tgt, *state, opts.Roots),
	)

	return append(results, protocolStages(ctx, tgt, opts)...)
}

// protocolStages runs the stages gated on the target's protocol.
func protocolStages(ctx context.Context, tgt target.Target, opts Options) []report.Result {
	switch tgt.Kind {
	case target.KindHTTPS:
		results := []report.Result{
			http2Stage(ctx, tgt, opts),
			redirectStage(ctx, tgt),
		}

		// The pyck stages talk to the gateway, so they chain after the app
		// domain rather than standing on their own.
		return append(results, pyckStages(ctx, tgt, opts)...)
	case target.KindGRPC:
		return grpcStages(ctx, tgt, opts)
	default:
		return nil
	}
}

// stage times fn and turns it into a Result.
func stage(tgt target.Target, name string, fn func() (bool, string)) report.Result {
	started := time.Now()
	ok, detail := fn()

	return report.Result{
		Ts:       started.UTC(),
		Target:   tgt.Addr(),
		Stage:    name,
		OK:       ok,
		Duration: time.Since(started),
		Detail:   detail,
	}
}

// closeAll closes every connection in conns.
func closeAll(conns []net.Conn) {
	for _, c := range conns {
		_ = c.Close()
	}
}
