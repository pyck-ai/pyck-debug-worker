// Package report holds the result model and the fixed-width renderers for the
// per-stage lines, the per-cycle summary block and the final run summary.
//
// The status set is exactly "ok" and "FAIL". There is no WARN, no INFO and no
// SKIP: a stage whose gate is not satisfied prints nothing at all.
package report

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Layouts and column widths of the rendered output.
const (
	// tsLayout is UTC RFC3339 at second precision.
	tsLayout = "2006-01-02T15:04:05Z"
	// clockLayout is the wall clock used for "last fail".
	clockLayout = "15:04:05"

	// Per-result line: <ts>  <target>  <stage>  <status>  <duration>  <detail>
	targetW = 24
	stageW  = 9
	durW    = 8

	// Summary rows: two leading spaces, the label padded by labelPad, the
	// rolled-up status right-aligned in statusW, the n/m counts right-aligned
	// in the widest counts value plus countsPad, then any extras.
	statusW   = 4
	labelPad  = 2
	countsPad = 3

	// blockW is the width of the ---- header and footer rules.
	blockW = 64

	// extraSep separates the counts column from the trailing extras.
	extraSep = "   "

	// overallLabel is the label of the rolled-up last row of every block.
	overallLabel = "OVERALL"
)

// Result is one probe stage outcome for one target.
type Result struct {
	Ts       time.Time
	Target   string
	Stage    string
	OK       bool
	Duration time.Duration
	Detail   string
}

// Line renders the result as a single fixed-width log line:
//
//	<ts>  <target>  <stage>  <status>  <duration>  <detail>
func (r Result) Line() string {
	line := fmt.Sprintf("%s  %-*s  %-*s  %*s  %*s  %s",
		r.Ts.UTC().Format(tsLayout),
		targetW, r.Target,
		stageW, r.Stage,
		statusW, lineStatus(r.OK),
		durW, formatDuration(r.Duration),
		r.Detail,
	)

	return strings.TrimRight(line, " ")
}

// Cycle is everything one probe cycle produced.
type Cycle struct {
	N        int
	At       time.Time
	Duration time.Duration
	Targets  []string
	Results  []Result
}

// OK reports whether every stage that ran in the cycle returned ok.
func (c Cycle) OK() bool {
	for _, r := range c.Results {
		if !r.OK {
			return false
		}
	}

	return true
}

// Run accumulates cycles and renders both the per-cycle block and the final
// run summary.
type Run struct {
	started time.Time
	targets []string

	cycles   int
	clean    int
	degraded int

	cumulative map[string]*counter
	lastOK     map[string]bool
	lastFail   map[string]time.Time

	failingSince time.Time
	anyFailed    bool
}

// counter is an ok-of-total tally.
type counter struct {
	ok    int
	total int
}

// NewRun starts a run at started, covering targets in the given order.
func NewRun(started time.Time, targets []string) *Run {
	return &Run{
		started:    started,
		targets:    append([]string(nil), targets...),
		cumulative: map[string]*counter{},
		lastOK:     map[string]bool{},
		lastFail:   map[string]time.Time{},
	}
}

// Failed reports whether any cycle in the run contained a failure. It stays
// true after recovery: a prober that hides a transient outage is useless.
func (r *Run) Failed() bool {
	return r.anyFailed
}

// Add records a cycle and returns its rendered summary block.
func (r *Run) Add(c Cycle) string {
	order, stats := tally(c)

	r.cycles++

	if c.OK() {
		r.clean++
		r.failingSince = time.Time{}
	} else {
		r.degraded++
		r.anyFailed = true

		if r.failingSince.IsZero() {
			r.failingSince = c.At
		}
	}

	for _, name := range order {
		s := stats[name]

		cum, ok := r.cumulative[name]
		if !ok {
			cum = &counter{}
			r.cumulative[name] = cum
		}

		cum.ok += s.ok
		cum.total += s.total

		targetOK := s.ok == s.total
		r.lastOK[name] = targetOK

		if !targetOK {
			r.lastFail[name] = c.At
		}
	}

	return r.renderCycle(c, order, stats)
}

// renderCycle renders one cycle summary block.
func (r *Run) renderCycle(c Cycle, order []string, stats map[string]*targetStat) string {
	rows := make([]row, 0, len(order)+1)
	overall := counter{}

	for _, name := range order {
		s := stats[name]
		overall.ok += s.ok
		overall.total += s.total

		rows = append(rows, row{
			label:  name,
			ok:     s.ok == s.total,
			counts: counts(s.ok, s.total),
			extra:  strings.Join(s.failed, " "),
		})
	}

	extra := "uptime " + formatDuration(c.At.Sub(r.started))
	if !r.failingSince.IsZero() {
		extra += "  failing " + formatDuration(c.At.Sub(r.failingSince))
	}

	rows = append(rows, row{
		label:  overallLabel,
		ok:     c.OK(),
		counts: counts(overall.ok, overall.total),
		extra:  extra,
	})

	title := fmt.Sprintf("cycle %d  %s  %s",
		c.N, c.At.UTC().Format(tsLayout), formatDuration(c.Duration))

	return block(title, rows)
}

// Summary renders the final run summary block.
func (r *Run) Summary(now time.Time) string {
	order := append([]string(nil), r.targets...)
	seen := map[string]bool{}

	for _, name := range order {
		seen[name] = true
	}

	for name := range r.cumulative {
		if !seen[name] {
			seen[name] = true

			order = append(order, name)
		}
	}

	rows := make([]row, 0, len(order)+1)
	overall := counter{}

	for _, name := range order {
		cum, ok := r.cumulative[name]
		if !ok {
			cum = &counter{}
		}

		overall.ok += cum.ok
		overall.total += cum.total

		extra := ""
		if at, ok := r.lastFail[name]; ok {
			extra = "last fail " + at.UTC().Format(clockLayout)
		}

		rows = append(rows, row{
			label:  name,
			ok:     r.lastOK[name] || cum.total == 0,
			counts: counts(cum.ok, cum.total),
			extra:  extra,
		})
	}

	rows = append(rows, row{
		label:  overallLabel,
		ok:     !r.anyFailed,
		counts: counts(overall.ok, overall.total),
		extra:  "uptime " + formatDuration(now.Sub(r.started)),
	})

	head := fmt.Sprintf("  cycles %d   clean %d   degraded %d", r.cycles, r.clean, r.degraded)

	return block("run summary ", rows, head)
}

// targetStat is one target's tally within a single cycle.
type targetStat struct {
	ok     int
	total  int
	failed []string
}

// tally groups a cycle's results per target, preserving the configured target
// order and appending any target that only appears in the results.
func tally(c Cycle) ([]string, map[string]*targetStat) {
	order := append([]string(nil), c.Targets...)
	stats := make(map[string]*targetStat, len(order))

	for _, name := range order {
		stats[name] = &targetStat{}
	}

	for _, res := range c.Results {
		s, ok := stats[res.Target]
		if !ok {
			s = &targetStat{}
			stats[res.Target] = s

			order = append(order, res.Target)
		}

		s.total++

		if res.OK {
			s.ok++

			continue
		}

		if !slices.Contains(s.failed, res.Stage) {
			s.failed = append(s.failed, res.Stage)
		}
	}

	return order, stats
}

// row is one rendered summary line.
type row struct {
	label  string
	ok     bool
	counts string
	extra  string
}

// block renders a titled ---- block: header rule, optional head lines, the
// rows, then the footer rule.
func block(title string, rows []row, head ...string) string {
	lines := make([]string, 0, len(rows)+len(head)+2)
	lines = append(lines, rule(title))
	lines = append(lines, head...)

	labelW, countsW := 0, 0
	for _, r := range rows {
		labelW = max(labelW, len(r.label))
		countsW = max(countsW, len(r.counts))
	}

	labelW += labelPad
	countsW += countsPad

	for _, r := range rows {
		line := fmt.Sprintf("  %-*s%*s%*s",
			labelW, r.label, statusW, rollupStatus(r.ok), countsW, r.counts)

		if r.extra != "" {
			line += extraSep + r.extra
		}

		lines = append(lines, line)
	}

	lines = append(lines, strings.Repeat("-", blockW))

	return strings.Join(lines, "\n")
}

// rule renders the "---- <title> ----…" header, padded to blockW.
func rule(title string) string {
	head := "---- " + title + " "
	if len(head) >= blockW {
		return head
	}

	return head + strings.Repeat("-", blockW-len(head))
}

// counts renders the n/m column.
func counts(ok, total int) string {
	return fmt.Sprintf("%d/%d", ok, total)
}

// lineStatus renders the per-stage status.
func lineStatus(ok bool) string {
	if ok {
		return "ok"
	}

	return "FAIL"
}

// rollupStatus renders the rolled-up status used in summary blocks.
func rollupStatus(ok bool) string {
	if ok {
		return "OK"
	}

	return "FAIL"
}

// formatDuration renders a duration compactly: millisecond precision below a
// second, centisecond precision below a minute, second precision above it,
// with trailing zero units dropped.
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}

	switch {
	case d < time.Second:
		d = d.Round(time.Millisecond)
	case d < time.Minute:
		d = d.Round(10 * time.Millisecond)
	default:
		d = d.Round(time.Second)
	}

	s := d.String()

	if strings.HasSuffix(s, "m0s") || strings.HasSuffix(s, "h0s") {
		s = strings.TrimSuffix(s, "0s")
	}

	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}

	return s
}
