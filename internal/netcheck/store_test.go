package netcheck

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// readLines decodes every JSON line of path into its "type" field order.
func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	defer file.Close()

	var out []map[string]any

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var line map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
			t.Fatalf("%s: line %q is not JSON: %v", path, scanner.Text(), err)
		}

		out = append(out, line)
	}

	return out
}

// types lists the "type" of each line.
func types(lines []map[string]any) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, l["type"].(string)) //nolint:forcetypeassert // test data
	}

	return out
}

func testHeader() header {
	return header{
		Type: "header", Version: "test", Hostname: "box", OS: "linux/amd64",
		Flags: headerFlags{Hosts: []string{"dev.pyck.cloud"}},
	}
}

func TestStoreRotatesPerUTCDay(t *testing.T) {
	dir := t.TempDir()
	s := newStore(dir, testHeader())

	day1 := time.Date(2026, 10, 19, 23, 59, 0, 0, time.UTC)
	day2 := day1.Add(time.Minute)

	if err := s.write(day1, aggregate{Type: "agg", TS: day1}); err != nil {
		t.Fatal(err)
	}

	// The 23:59 minute is flushed at midnight: that closes day 1.
	if err := s.flush(day2); err != nil {
		t.Fatal(err)
	}

	if s.file != nil {
		t.Error("finished day still open after the midnight flush")
	}

	if err := s.writeEvent(event{Type: "event", TS: day2, Event: eventDrop}); err != nil {
		t.Fatal(err)
	}

	s.close()

	if got := types(readLines(t, filepath.Join(dir, "2026-10-19.json"))); !slices.Equal(got, []string{"header", "agg"}) {
		t.Errorf("day 1 lines = %v", got)
	}

	if got := types(readLines(t, filepath.Join(dir, "2026-10-20.json"))); !slices.Equal(got, []string{"header", "event"}) {
		t.Errorf("day 2 lines = %v", got)
	}
}

func TestStoreResumesAfterRestart(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)

	first := newStore(dir, testHeader())
	if err := first.write(ts, aggregate{Type: "agg", TS: ts}); err != nil {
		t.Fatal(err)
	}

	if err := first.flush(ts); err != nil {
		t.Fatal(err)
	}

	// A crash: no close. Everything flushed so far must survive.
	second := newStore(dir, testHeader())
	if err := second.write(ts.Add(time.Minute), aggregate{Type: "agg", TS: ts.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}

	second.close()

	lines := readLines(t, filepath.Join(dir, "2026-10-19.json"))
	if got := types(lines); !slices.Equal(got, []string{"header", "agg", "agg"}) {
		t.Errorf("resumed file lines = %v, want one header and both aggregates", got)
	}

	if lines[0]["hostname"] != "box" {
		t.Errorf("header = %v", lines[0])
	}
}

func TestStoreFinished(t *testing.T) {
	dir := t.TempDir()

	for _, name := range []string{"2026-10-18.json", "2026-10-19.json.sent", "2026-10-20.json", "2026-10-21.json", "notes.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	s := newStore(dir, testHeader())

	// Day 20 is still open, as if midnight's flush has not happened yet.
	open := time.Date(2026, 10, 20, 23, 59, 0, 0, time.UTC)
	if err := s.write(open, aggregate{Type: "agg", TS: open}); err != nil {
		t.Fatal(err)
	}

	got, err := s.finished(time.Date(2026, 10, 21, 0, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}

	want := []string{filepath.Join(dir, "2026-10-18.json"), filepath.Join(dir, "2026-10-20.json")}
	if !slices.Equal(got, want) {
		t.Errorf("finished = %v, want %v", got, want)
	}

	if s.file != nil {
		t.Error("finished() left a past day open")
	}

	if lines := readLines(t, want[1]); len(lines) != 2 {
		t.Errorf("past day not flushed before upload: %d lines", len(lines))
	}
}
