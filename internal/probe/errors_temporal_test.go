package probe

import (
	"fmt"
	"testing"

	"go.temporal.io/api/serviceerror"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Temporal's serviceerror types implement Status(), not GRPCStatus(), so the
// standard status helpers do not see them. Every Temporal fault would fall
// through the taxonomy unclassified if the classifier did not handle both.
func TestCodeOfSeesTemporalServiceErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{
			name: "namespace not found",
			err:  serviceerror.NewNamespaceNotFound("no-such-namespace"),
			want: codes.NotFound,
		},
		{
			// Temporal has no Unauthenticated serviceerror type: the frontend
			// returns a plain gRPC status for a rejected key.
			name: "unauthenticated arrives as a plain status",
			err:  status.Error(codes.Unauthenticated, "bad key"),
			want: codes.Unauthenticated,
		},
		{
			name: "permission denied",
			err:  serviceerror.NewPermissionDenied("nope", "no scope"),
			want: codes.PermissionDenied,
		},
		{
			name: "resource exhausted",
			err:  &serviceerror.ResourceExhausted{Message: "slow down"},
			want: codes.ResourceExhausted,
		},
		{
			name: "unavailable",
			err:  serviceerror.NewUnavailable("frontend is down"),
			want: codes.Unavailable,
		},
		{
			name: "wrapped",
			err:  fmt.Errorf("describe: %w", serviceerror.NewNamespaceNotFound("x")),
			want: codes.NotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := codeOf(tc.err)
			if !ok {
				t.Fatalf("codeOf did not recognise %T", tc.err)
			}

			if got != tc.want {
				t.Errorf("codeOf() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNamespaceVerdictOnRealServiceError(t *testing.T) {
	ok, detail := namespaceVerdict(nil, serviceerror.NewNamespaceNotFound("no-such-namespace"))
	if ok {
		t.Fatal("ok = true, want false")
	}

	if detail != "namespace not found: a typo, not an auth fault" {
		t.Errorf("detail = %q: the taxonomy did not classify a real Temporal error", detail)
	}
}

func TestSystemInfoVerdictOnRealServiceError(t *testing.T) {
	ok, detail := systemInfoVerdict(nil, status.Error(codes.Unauthenticated, "bad key"), true)
	if ok {
		t.Fatal("ok = true, want false")
	}

	if detail != "unauthenticated: bad API key — health answered, so this is definitively auth, not the network" {
		t.Errorf("detail = %q", detail)
	}
}
