package report

import (
	"strings"
	"testing"
	"time"
)

// ts is a fixed UTC instant helper for the tests.
func ts(hour, minute, second int) time.Time {
	return time.Date(2026, 9, 4, hour, minute, second, 0, time.UTC)
}

// results builds n results for a target, the first failed ones carrying the
// given stage names.
func results(target string, total int, failedStages ...string) []Result {
	out := make([]Result, 0, total)

	for _, stage := range failedStages {
		out = append(out, Result{Target: target, Stage: stage, OK: false})
	}

	for range total - len(failedStages) {
		out = append(out, Result{Target: target, Stage: "dns", OK: true})
	}

	return out
}

func TestResultLine(t *testing.T) {
	tests := []struct {
		name string
		in   Result
		want string
	}{
		{
			name: "ok with detail",
			in: Result{
				Ts:       ts(9, 41, 1),
				Target:   "wf.test.pyck.cloud:443",
				Stage:    "tls",
				OK:       true,
				Duration: 42 * time.Millisecond,
				Detail:   "TLS1.3 X25519MLKEM768",
			},
			want: "2026-09-04T09:41:01Z  wf.test.pyck.cloud:443    tls          ok      42ms  TLS1.3 X25519MLKEM768",
		},
		{
			name: "fail with detail",
			in: Result{
				Ts:       ts(9, 43, 37),
				Target:   "wf.test.pyck.cloud:443",
				Stage:    "temporal",
				OK:       false,
				Duration: 2 * time.Second,
				Detail:   "Unauthenticated",
			},
			want: "2026-09-04T09:43:37Z  wf.test.pyck.cloud:443    temporal   FAIL        2s  Unauthenticated",
		},
		{
			name: "empty detail has no trailing space",
			in: Result{
				Ts:       ts(9, 41, 1),
				Target:   "test.pyck.cloud:443",
				Stage:    "dns",
				OK:       true,
				Duration: 3 * time.Millisecond,
			},
			want: "2026-09-04T09:41:01Z  test.pyck.cloud:443       dns          ok       3ms",
		},
		{
			name: "non-utc timestamp is rendered as utc",
			in: Result{
				Ts:       ts(9, 41, 1).In(time.FixedZone("x", 2*60*60)),
				Target:   "test.pyck.cloud:443",
				Stage:    "dns",
				OK:       true,
				Duration: time.Millisecond,
			},
			want: "2026-09-04T09:41:01Z  test.pyck.cloud:443       dns          ok       1ms",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.Line(); got != tc.want {
				t.Errorf("Line()\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestCycleBlock(t *testing.T) {
	const (
		wf  = "wf.test.pyck.cloud:443"
		app = "test.pyck.cloud:443"
	)

	targets := []string{wf, app}

	tests := []struct {
		name    string
		started time.Time
		cycles  []Cycle
		want    []string
	}{
		{
			name:    "all ok",
			started: ts(9, 40, 31),
			cycles: []Cycle{{
				N:        1,
				At:       ts(9, 41, 1),
				Duration: 1310 * time.Millisecond,
				Targets:  targets,
				Results:  append(results(wf, 11), results(app, 6)...),
			}},
			want: []string{
				"---- cycle 1  2026-09-04T09:41:01Z  1.31s ----------------------\n" +
					"  wf.test.pyck.cloud:443    OK   11/11\n" +
					"  test.pyck.cloud:443       OK     6/6\n" +
					"  OVERALL                   OK   17/17   uptime 30s\n" +
					"----------------------------------------------------------------",
			},
		},
		{
			name:    "failure names the failing stages and reports failing time",
			started: ts(9, 40, 52),
			cycles: []Cycle{
				{
					N:        5,
					At:       ts(9, 42, 22),
					Duration: 5210 * time.Millisecond,
					Targets:  targets,
					Results:  append(results(wf, 11, "tcp(ipv6)", "temporal"), results(app, 6)...),
				},
				{
					N:        6,
					At:       ts(9, 43, 37),
					Duration: 5210 * time.Millisecond,
					Targets:  targets,
					Results:  append(results(wf, 11, "tcp(ipv6)", "temporal"), results(app, 6)...),
				},
			},
			want: []string{
				"---- cycle 5  2026-09-04T09:42:22Z  5.21s ----------------------\n" +
					"  wf.test.pyck.cloud:443  FAIL    9/11   tcp(ipv6) temporal\n" +
					"  test.pyck.cloud:443       OK     6/6\n" +
					"  OVERALL                 FAIL   15/17   uptime 1m30s  failing 0s\n" +
					"----------------------------------------------------------------",
				"---- cycle 6  2026-09-04T09:43:37Z  5.21s ----------------------\n" +
					"  wf.test.pyck.cloud:443  FAIL    9/11   tcp(ipv6) temporal\n" +
					"  test.pyck.cloud:443       OK     6/6\n" +
					"  OVERALL                 FAIL   15/17   uptime 2m45s  failing 1m15s\n" +
					"----------------------------------------------------------------",
			},
		},
		{
			name:    "no results yet",
			started: ts(9, 40, 31),
			cycles: []Cycle{{
				N:        1,
				At:       ts(9, 40, 31),
				Duration: 2 * time.Millisecond,
				Targets:  targets,
			}},
			want: []string{
				"---- cycle 1  2026-09-04T09:40:31Z  2ms ------------------------\n" +
					"  wf.test.pyck.cloud:443    OK   0/0\n" +
					"  test.pyck.cloud:443       OK   0/0\n" +
					"  OVERALL                   OK   0/0   uptime 0s\n" +
					"----------------------------------------------------------------",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			run := NewRun(tc.started, targets)

			for i, c := range tc.cycles {
				got := run.Add(c)
				if got != tc.want[i] {
					t.Errorf("cycle %d block mismatch\n got:\n%s\nwant:\n%s", c.N, got, tc.want[i])
				}
			}
		})
	}
}

func TestRunSummaryAfterTransientFailure(t *testing.T) {
	const (
		wf  = "wf.test.pyck.cloud:443"
		app = "test.pyck.cloud:443"
	)

	targets := []string{wf, app}
	run := NewRun(ts(9, 40, 31), targets)

	run.Add(Cycle{
		N: 1, At: ts(9, 41, 1), Duration: time.Second, Targets: targets,
		Results: append(results(wf, 11), results(app, 6)...),
	})
	run.Add(Cycle{
		N: 2, At: ts(9, 41, 31), Duration: time.Second, Targets: targets,
		Results: append(results(wf, 11, "temporal"), results(app, 6)...),
	})
	run.Add(Cycle{
		N: 3, At: ts(9, 42, 1), Duration: time.Second, Targets: targets,
		Results: append(results(wf, 11), results(app, 6)...),
	})

	want := "---- run summary  ----------------------------------------------\n" +
		"  cycles 3   clean 2   degraded 1\n" +
		"  wf.test.pyck.cloud:443    OK   32/33   last fail 09:41:31\n" +
		"  test.pyck.cloud:443       OK   18/18\n" +
		"  OVERALL                 FAIL   50/51   uptime 1m30s\n" +
		"----------------------------------------------------------------"

	if got := run.Summary(ts(9, 42, 1)); got != want {
		t.Errorf("Summary()\n got:\n%s\nwant:\n%s", got, want)
	}

	if !run.Failed() {
		t.Error("Failed() = false, want true: the run contained a degraded cycle")
	}
}

func TestRunSummaryCleanRun(t *testing.T) {
	targets := []string{"test.pyck.cloud:443"}
	run := NewRun(ts(9, 40, 31), targets)

	run.Add(Cycle{
		N: 1, At: ts(9, 41, 1), Duration: time.Second, Targets: targets,
		Results: results("test.pyck.cloud:443", 6),
	})

	if run.Failed() {
		t.Error("Failed() = true, want false")
	}

	got := run.Summary(ts(9, 41, 1))
	if !strings.Contains(got, "OVERALL") || strings.Contains(got, "FAIL") {
		t.Errorf("clean run summary must not contain FAIL:\n%s", got)
	}
}

func TestCycleOK(t *testing.T) {
	tests := []struct {
		name string
		in   Cycle
		want bool
	}{
		{name: "empty", in: Cycle{}, want: true},
		{name: "all ok", in: Cycle{Results: results("a", 3)}, want: true},
		{name: "one failure", in: Cycle{Results: results("a", 3, "tcp")}, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.OK(); got != tc.want {
				t.Errorf("OK() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		{in: 0, want: "0s"},
		{in: -time.Second, want: "0s"},
		{in: 3 * time.Millisecond, want: "3ms"},
		{in: 1310 * time.Millisecond, want: "1.31s"},
		{in: 30 * time.Second, want: "30s"},
		{in: 70 * time.Second, want: "1m10s"},
		{in: 21 * time.Minute, want: "21m"},
		{in: time.Hour, want: "1h"},
		{in: 90 * time.Minute, want: "1h30m"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := formatDuration(tc.in); got != tc.want {
				t.Errorf("formatDuration(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
