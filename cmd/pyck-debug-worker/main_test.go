package main

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"testing"
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
