package netcheck

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"
)

// dayLayout names the daily files: one per UTC day.
const dayLayout = "2006-01-02"

// fileExt is the extension of a day file; sentExt is appended once uploaded.
const (
	fileExt = ".json"
	sentExt = ".sent"
)

// header is the first line of every day file.
type header struct {
	Type     string      `json:"type"`
	Version  string      `json:"version"`
	Hostname string      `json:"hostname"`
	OS       string      `json:"os"`
	Flags    headerFlags `json:"flags"`
}

// headerFlags records the netcheck flags the file was written under.
type headerFlags struct {
	Hosts  []string `json:"hosts"`
	Upload bool     `json:"upload"`
}

// event is a point-in-time occurrence: IP added/removed, drop, server close,
// resolve failure.
type event struct {
	Type      string    `json:"type"`
	TS        time.Time `json:"ts"`
	Event     string    `json:"event"`
	Host      string    `json:"host"`
	IP        string    `json:"ip,omitempty"`
	Mode      string    `json:"mode,omitempty"`
	LifetimeS float64   `json:"lifetime_s,omitempty"`
	// Fingerprint (leaf SHA-256) and Issuer (CN) describe an intercepted
	// certificate.
	Fingerprint string `json:"fingerprint,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
	Error       string `json:"error,omitempty"`
	// Class is how a dropped connection died (timeout, reset, other), Phase
	// when a reset arrived (hello, transfer, idle).
	Class string `json:"class,omitempty"`
	Phase string `json:"phase,omitempty"`
	// GapS is the idle gap after which an idle connection died, SurvivedS
	// the longest gap it had survived before.
	GapS      float64 `json:"gap_s,omitempty"`
	SurvivedS float64 `json:"survived_s,omitempty"`
	// Resolver names the resolver of a resolver-unreachable event; Answers
	// are every resolver's A records of a dns-mismatch event.
	Resolver string              `json:"resolver,omitempty"`
	Answers  map[string][]string `json:"answers,omitempty"`
	// Path and PrevPath are a route-changed event's hop IPs, "*" for a
	// silent TTL.
	Path     []string `json:"path,omitempty"`
	PrevPath []string `json:"prev_path,omitempty"`
}

// Event names.
const (
	eventIPAdded      = "ip-added"
	eventIPRemoved    = "ip-removed"
	eventDrop         = "drop"
	eventServerClosed = "server-closed"
	eventResolveFail  = "resolve-failed"
	eventIntercepted  = "intercepted"
	eventDNSMismatch  = "dns-mismatch"
	eventUnreachable  = "resolver-unreachable"
	eventRouteChanged = "route-changed"
)

// newEvent stamps an event now.
func newEvent(name string, t Target) event {
	ev := event{Type: "event", TS: time.Now().UTC(), Event: name, Host: t.Host}
	if t.IP.IsValid() {
		ev.IP = t.IP.String()
	}

	return ev
}

// writeEvent appends ev; it reaches disk with the next minute flush.
func (s *store) writeEvent(ev event) error {
	return s.write(ev.TS, ev)
}

// osName is GOOS/GOARCH.
func osName() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

// store appends JSON lines to the file of the record's UTC day. Writes are
// buffered and flushed once a minute; a restart resumes appending to the
// same day's file.
type store struct {
	dir    string
	header header

	mu   sync.Mutex
	day  string
	file *os.File
	buf  *bufio.Writer
}

func newStore(dir string, h header) *store {
	return &store{dir: dir, header: h}
}

// write appends v as one JSON line to the file for ts's UTC day.
func (s *store) write(ts time.Time, v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("netcheck: encode: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.open(ts.UTC().Format(dayLayout)); err != nil {
		return err
	}

	if _, err := s.buf.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("netcheck: write %s: %w", s.file.Name(), err)
	}

	return nil
}

// open makes day the current file, closing the previous one. A new or empty
// file gets the header first.
func (s *store) open(day string) error {
	if s.file != nil && s.day == day {
		return nil
	}

	if err := s.closeLocked(); err != nil {
		return err
	}

	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return fmt.Errorf("netcheck: %w", err)
	}

	path := filepath.Join(s.dir, day+fileExt)

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640) //nolint:gosec // path is dir + a formatted date
	if err != nil {
		return fmt.Errorf("netcheck: %w", err)
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()

		return fmt.Errorf("netcheck: %w", err)
	}

	s.day, s.file, s.buf = day, file, bufio.NewWriter(file)

	if info.Size() == 0 {
		line, err := json.Marshal(s.header)
		if err != nil {
			return fmt.Errorf("netcheck: encode header: %w", err)
		}

		if _, err := s.buf.Write(append(line, '\n')); err != nil {
			return fmt.Errorf("netcheck: write %s: %w", path, err)
		}
	}

	return nil
}

// flush writes buffered lines to disk, and closes the current file once its
// day is over, so a finished day is complete and free to be uploaded.
func (s *store) flush(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.file == nil {
		return nil
	}

	if s.day < now.UTC().Format(dayLayout) {
		return s.closeLocked()
	}

	if err := s.buf.Flush(); err != nil {
		return fmt.Errorf("netcheck: write %s: %w", s.file.Name(), err)
	}

	return nil
}

// close flushes and closes the current file.
func (s *store) close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	_ = s.closeLocked()
}

func (s *store) closeLocked() error {
	if s.file == nil {
		return nil
	}

	err := errors.Join(s.buf.Flush(), s.file.Close())
	s.file, s.buf, s.day = nil, nil, ""

	if err != nil {
		return fmt.Errorf("netcheck: %w", err)
	}

	return nil
}

// finished returns the unsent day files before now's UTC day, oldest first.
// A still-open past day is closed first.
func (s *store) finished(now time.Time) ([]string, error) {
	today := now.UTC().Format(dayLayout)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.file != nil && s.day < today {
		if err := s.closeLocked(); err != nil {
			return nil, err
		}
	}

	paths, err := filepath.Glob(filepath.Join(s.dir, "????-??-??"+fileExt))
	if err != nil {
		return nil, fmt.Errorf("netcheck: %w", err)
	}

	var days []string

	for _, path := range paths {
		day, err := time.Parse(dayLayout, dayOf(path))
		if err != nil || day.Format(dayLayout) >= today {
			continue
		}

		days = append(days, path)
	}

	sort.Strings(days)

	return days, nil
}

// dayOf is the YYYY-MM-DD part of a day file's path.
func dayOf(path string) string {
	base := filepath.Base(path)

	return base[:len(base)-len(fileExt)]
}
