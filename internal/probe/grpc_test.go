package probe

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

func TestHealthVerdict(t *testing.T) {
	serving := &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}
	notServing := &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_NOT_SERVING}

	tests := []struct {
		name     string
		resp     *healthpb.HealthCheckResponse
		err      error
		wantOK   bool
		contains string
	}{
		{name: "serving", resp: serving, wantOK: true, contains: "SERVING"},
		{name: "not serving", resp: notServing, wantOK: false, contains: "NOT_SERVING"},
		{
			// A well-formed gRPC status over h2 proves the transport works,
			// which is all this stage measures.
			name:     "unimplemented is reachability, not failure",
			err:      status.Error(codes.Unimplemented, "unknown service grpc.health.v1.Health"),
			wantOK:   true,
			contains: "reachable, health API absent",
		},
		{
			name:     "not found is the health API answering",
			err:      status.Error(codes.NotFound, "unknown service"),
			wantOK:   true,
			contains: "reachable, health API does not know",
		},
		{
			name:     "unavailable is a transport failure",
			err:      status.Error(codes.Unavailable, "connection error"),
			wantOK:   false,
			contains: "unavailable:",
		},
		{
			name:     "unauthenticated",
			err:      status.Error(codes.Unauthenticated, "bad token"),
			wantOK:   false,
			contains: "unauthenticated: bad API key",
		},
		{
			name:     "permission denied",
			err:      status.Error(codes.PermissionDenied, "nope"),
			wantOK:   false,
			contains: "not authorised for this namespace",
		},
		{
			name:     "resource exhausted is reported but still incomplete",
			err:      status.Error(codes.ResourceExhausted, "slow down"),
			wantOK:   false,
			contains: "rate-limited but healthy",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, detail := healthVerdict(tc.resp, tc.err)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v (detail %q)", ok, tc.wantOK, detail)
			}

			if !strings.Contains(detail, tc.contains) {
				t.Errorf("detail %q does not contain %q", detail, tc.contains)
			}
		})
	}
}

func TestGRPCReason(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantOK  bool
		want    string
		prefix  string
		useWant bool
	}{
		{
			name: "unauthenticated", err: status.Error(codes.Unauthenticated, "x"),
			wantOK: true, want: "unauthenticated: bad API key", useWant: true,
		},
		{
			name: "permission denied", err: status.Error(codes.PermissionDenied, "x"),
			wantOK:  true,
			want:    "permission denied: not authorised for this namespace (rejected key or wrong scope)",
			useWant: true,
		},
		{
			name: "resource exhausted", err: status.Error(codes.ResourceExhausted, "x"),
			wantOK: true, want: "resource exhausted: rate-limited but healthy", useWant: true,
		},
		{
			name: "unavailable", err: status.Error(codes.Unavailable, "no substream"),
			wantOK: true, prefix: "unavailable: ",
		},
		{
			name: "deadline", err: status.Error(codes.DeadlineExceeded, "x"),
			wantOK: true, prefix: "deadline exceeded before any status",
		},
		{
			name: "internal falls through to code and message",
			err:  status.Error(codes.Internal, "boom"),
			// The default arm keeps the code visible rather than inventing a
			// verdict for a code the taxonomy does not cover.
			wantOK: true, want: "Internal: boom", useWant: true,
		},
		{name: "plain error carries no status", err: errors.New("nope"), wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := grpcReason(tc.err)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (got %q)", ok, tc.wantOK, got)
			}

			switch {
			case !ok:
			case tc.useWant && got != tc.want:
				t.Errorf("grpcReason() = %q, want %q", got, tc.want)
			case tc.prefix != "" && !strings.HasPrefix(got, tc.prefix):
				t.Errorf("grpcReason() = %q, want prefix %q", got, tc.prefix)
			}
		})
	}
}

func TestClassifyUsesGRPCStatus(t *testing.T) {
	got := classify(status.Error(codes.Unauthenticated, "bad key"))
	if got != "unauthenticated: bad API key" {
		t.Errorf("classify() = %q", got)
	}
}
