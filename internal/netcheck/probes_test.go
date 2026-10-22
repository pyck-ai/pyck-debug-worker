package netcheck

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/pyck-ai/pyck-debug-worker/internal/report"
)

func TestProbeLoop(t *testing.T) {
	dir := t.TempDir()
	store := newStore(dir, testHeader())
	probes := make(chan []report.Result, 2)
	ts := time.Now().UTC().Truncate(time.Second)

	// Queued before the loop even starts, with ctx already over: still
	// written, so the last cycle before a shutdown is not lost.
	probes <- []report.Result{
		{Ts: ts, Target: "dev.pyck.cloud:443", Stage: "tls", OK: true, Duration: 42 * time.Millisecond, Detail: "TLS1.3"},
		{Ts: ts, Target: "dev.pyck.cloud:443", Stage: "auth", OK: false, Duration: time.Second, Detail: "401"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	probeLoop(ctx, probes, store)
	store.close()

	lines := readLines(t, filepath.Join(dir, ts.Format(dayLayout)+fileExt))
	if len(lines) != 3 {
		t.Fatalf("file = %v, want the header and two probe records", lines)
	}

	first, second := lines[1], lines[2]

	if first["type"] != "probe" || first["target"] != "dev.pyck.cloud:443" || first["stage"] != "tls" ||
		first["ok"] != true || first["duration_ms"] != float64(42) || first["detail"] != "TLS1.3" ||
		first["ts"] != ts.Format(time.RFC3339) {
		t.Errorf("first = %v", first)
	}

	if second["ok"] != false || second["stage"] != "auth" || second["duration_ms"] != float64(1000) {
		t.Errorf("second = %v", second)
	}
}
