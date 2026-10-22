package main

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pyck-ai/pyck-debug-worker/internal/netcheck"
	"github.com/pyck-ai/pyck-debug-worker/internal/report"
)

func TestNetcheckFlagsRefused(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "upload without netcheck", args: []string{"--env", "test", "--netcheck-upload"}, want: "--netcheck-upload requires --netcheck"},
		{name: "hosts without netcheck", args: []string{"--env", "test", "--netcheck-hosts=dev.pyck.cloud"}, want: "--netcheck-hosts requires --netcheck"},
		{name: "full URL", args: []string{"--env", "test", "--netcheck", "--netcheck-hosts=https://dev.pyck.cloud/"}, want: "not a hostname"},
		{name: "empty entry", args: []string{"--env", "test", "--netcheck", "--netcheck-hosts=dev.pyck.cloud,"}, want: "empty entry"},
		{name: "duplicate", args: []string{"--env", "test", "--netcheck", "--netcheck-hosts=dev.pyck.cloud,dev.pyck.cloud"}, want: "listed twice"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer

			if code := run(tc.args, io.Discard, &stderr); code != exitUsage {
				t.Errorf("exit = %d, want %d", code, exitUsage)
			}

			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr %q lacks %q", stderr.String(), tc.want)
			}
		})
	}
}

func TestNetcheckFlagsAccepted(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		on     bool
		upload bool
		hosts  []string
	}{
		{name: "off", args: []string{"--env", "test"}},
		{name: "default host", args: []string{"--env", "test", "--netcheck"}, on: true, hosts: []string{"dev.pyck.cloud"}},
		{
			name:   "hosts and upload",
			args:   []string{"--env", "test", "--netcheck", "--netcheck-upload", "--netcheck-hosts=region-sing.pyck.cloud,192.0.2.10"},
			on:     true,
			upload: true,
			hosts:  []string{"region-sing.pyck.cloud", "192.0.2.10"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseFlags(tc.args, io.Discard)
			if err != nil {
				t.Fatalf("parseFlags: %v", err)
			}

			if cfg.netcheck != tc.on || cfg.netcheckUpload != tc.upload || !slices.Equal(cfg.netcheckHosts, tc.hosts) {
				t.Errorf("got netcheck=%v upload=%v hosts=%v", cfg.netcheck, cfg.netcheckUpload, cfg.netcheckHosts)
			}
		})
	}
}

func TestPersistProbes(t *testing.T) {
	results := []report.Result{{Target: "dev.pyck.cloud:443", Stage: "tls", OK: true}}

	// Netcheck off: nothing to hand over, nothing happens.
	persistProbes(nil, results)
	persistProbes(&netcheck.Config{}, results)

	nc := &netcheck.Config{Probes: make(chan []report.Result, 1)}
	persistProbes(nc, results)

	if got := <-nc.Probes; len(got) != 1 || got[0].Stage != "tls" {
		t.Errorf("handed over %v", got)
	}

	// A full queue drops the cycle instead of blocking the probe loop.
	nc.Probes <- results

	done := make(chan struct{})

	go func() {
		persistProbes(nc, results)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("persistProbes blocked on a full queue")
	}
}
