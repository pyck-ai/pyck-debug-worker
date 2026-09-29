package main

import (
	"errors"
	"io"
	"testing"

	"github.com/pyck-ai/pyck-debug-worker/internal/printcheck"
)

func TestParseFlagsPrintMode(t *testing.T) {
	tests := []struct {
		args []string
		want printcheck.Mode
	}{
		{args: nil, want: printcheck.ModeRPC},
		{args: []string{"--print-mode=rpc"}, want: printcheck.ModeRPC},
		{args: []string{"--print-mode=smb"}, want: printcheck.ModeSMB},
	}

	for _, tc := range tests {
		cfg, err := parseFlags(tc.args, io.Discard)
		if err != nil {
			t.Fatalf("parseFlags(%q) error = %v", tc.args, err)
		}

		if cfg.printMode != tc.want {
			t.Errorf("parseFlags(%q) printMode = %q, want %q", tc.args, cfg.printMode, tc.want)
		}
	}
}

func TestParseFlagsRejectsUnknownPrintMode(t *testing.T) {
	_, err := parseFlags([]string{"--print-mode=foo"}, io.Discard)
	if !errors.Is(err, errUsage) {
		t.Fatalf("parseFlags(--print-mode=foo) error = %v, want errUsage", err)
	}
}
