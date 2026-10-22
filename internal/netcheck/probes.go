package netcheck

import (
	"context"
	"time"

	"github.com/pyck-ai/pyck-debug-worker/internal/report"
)

// probeRecord is one --env probe stage result, exactly as printed: the
// printed line never carries a secret, so neither does this.
type probeRecord struct {
	Type       string    `json:"type"`
	TS         time.Time `json:"ts"`
	Target     string    `json:"target"`
	Stage      string    `json:"stage"`
	OK         bool      `json:"ok"`
	DurationMS float64   `json:"duration_ms"`
	Detail     string    `json:"detail,omitempty"`
}

// probeLoop writes every probe result it receives until ctx ends, then the
// ones already queued.
func probeLoop(ctx context.Context, probes <-chan []report.Result, store *store) {
	for {
		select {
		case results := <-probes:
			writeProbes(store, results)
		case <-ctx.Done():
			for {
				select {
				case results := <-probes:
					writeProbes(store, results)
				default:
					return
				}
			}
		}
	}
}

// writeProbes appends one probe record per result.
func writeProbes(store *store, results []report.Result) {
	for _, r := range results {
		_ = store.write(r.Ts, probeRecord{
			Type:       "probe",
			TS:         r.Ts.UTC(),
			Target:     r.Target,
			Stage:      r.Stage,
			OK:         r.OK,
			DurationMS: round(ms(r.Duration)),
			Detail:     r.Detail,
		})
	}
}
