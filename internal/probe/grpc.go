package probe

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/pyck-ai/pyck-debug-worker/internal/report"
	"github.com/pyck-ai/pyck-debug-worker/internal/target"
)

// healthService is the service name asked about in the health check.
const healthService = "temporal.api.workflowservice.v1.WorkflowService"

// gRPC stage budgets.
const (
	// connectTimeout bounds how long the connection may take to report Ready.
	connectTimeout = 5 * time.Second
	// rpcTimeout bounds a single unary call.
	rpcTimeout = 5 * time.Second
)

// grpcStages runs the grpc and health stages over one shared connection.
func grpcStages(ctx context.Context, tgt target.Target, opts Options) []report.Result {
	var conn *grpc.ClientConn

	connect := stage(tgt, "grpc", func() (bool, string) {
		client, ok, detail := connectGRPC(ctx, tgt, opts)
		if !ok {
			return false, detail
		}

		conn = client

		return true, detail
	})

	results := []report.Result{connect}

	if conn == nil {
		return results
	}

	// The connection belongs to the cache and outlives this cycle.
	health := healthStage(ctx, tgt, conn)
	results = append(results, health)

	return append(results, temporalStages(ctx, tgt, opts, health.OK)...)
}

// connectGRPC returns the persistent connection for a target and waits until
// it reports Ready.
//
// grpc.NewClient performs no I/O whatsoever: a nil error from it means the
// target string and the dial options parsed, and nothing more. Reporting that
// as a connection would make the stage green against an unreachable host, so
// readiness — observed through the connectivity state machine — is the only
// thing this stage treats as success.
//
// The connection is cached across cycles, so the detail names the state it was
// found in: a channel that had to climb back out of TRANSIENT_FAILURE is a
// different observation from one that was already serving.
func connectGRPC(ctx context.Context, tgt target.Target, opts Options) (*grpc.ClientConn, bool, string) {
	mode := "tls"
	if opts.Insecure {
		mode = "plaintext"
	}

	conn, fresh, err := opts.Clients.grpcConn(tgt, opts)
	if err != nil {
		return nil, false, "client rejected the configuration: " + classify(err)
	}

	before := conn.GetState()

	conn.Connect()

	readyCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	if ok, detail := waitReady(readyCtx, conn); !ok {
		return nil, false, detail
	}

	switch {
	case fresh:
		return conn, true, "READY " + mode
	case before == connectivity.Ready:
		return conn, true, "READY " + mode + " reused"
	default:
		return conn, true, "READY " + mode + " recovered from " + before.String()
	}
}

// waitReady blocks until the connection reports Ready.
func waitReady(ctx context.Context, conn *grpc.ClientConn) (bool, string) {
	for {
		state := conn.GetState()

		switch state {
		case connectivity.Ready:
			return true, ""
		case connectivity.TransientFailure:
			return false, "connection attempt failed (TRANSIENT_FAILURE)"
		case connectivity.Shutdown:
			return false, "connection shut down"
		case connectivity.Idle, connectivity.Connecting:
		}

		if !conn.WaitForStateChange(ctx, state) {
			return false, state.String() + ": " + classify(ctx.Err())
		}
	}
}

// healthStage asks the standard gRPC health service about the Temporal
// workflow service.
//
// Unimplemented and NotFound are successes: both are well-formed gRPC statuses
// carried over h2, which is exactly what this stage is measuring. Only a
// transport-level failure means the endpoint could not be reached.
func healthStage(ctx context.Context, tgt target.Target, conn *grpc.ClientConn) report.Result {
	return stage(tgt, "health", func() (bool, string) {
		callCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
		defer cancel()

		resp, err := healthpb.NewHealthClient(conn).Check(callCtx, &healthpb.HealthCheckRequest{
			Service: healthService,
		})

		return healthVerdict(resp, err)
	})
}

// healthVerdict judges a health check answer.
func healthVerdict(resp *healthpb.HealthCheckResponse, err error) (bool, string) {
	if err == nil {
		if resp.GetStatus() == healthpb.HealthCheckResponse_SERVING {
			return true, resp.GetStatus().String()
		}

		return false, resp.GetStatus().String()
	}

	code, _ := codeOf(err)

	switch code {
	case codes.Unimplemented:
		// A well-formed gRPC status carried over h2 is exactly the evidence
		// this stage exists to collect. The health API being absent says
		// nothing about reachability.
		return true, "reachable, health API absent"
	case codes.NotFound:
		return true, "reachable, health API does not know " + healthService
	default:
		return false, classify(err)
	}
}
