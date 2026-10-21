package netcheck

import (
	"errors"
	"slices"
	"testing"
)

func TestParseHosts(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []string
		wantErr bool
	}{
		{name: "default", in: DefaultHosts, want: []string{"dev.pyck.cloud"}},
		{
			name: "several, trimmed and lowercased",
			in:   "region-sing.pyck.cloud, Dev.pyck.cloud",
			want: []string{"region-sing.pyck.cloud", "dev.pyck.cloud"},
		},
		{name: "bare IPv4", in: "192.0.2.10", want: []string{"192.0.2.10"}},
		{name: "bare IPv6", in: "2001:db8::1", want: []string{"2001:db8::1"}},
		{name: "URL", in: "https://dev.pyck.cloud", wantErr: true},
		{name: "path", in: "dev.pyck.cloud/static", wantErr: true},
		{name: "port", in: "dev.pyck.cloud:443", wantErr: true},
		{name: "empty", in: "", wantErr: true},
		{name: "empty entry", in: "dev.pyck.cloud,,region-sing.pyck.cloud", wantErr: true},
		{name: "trailing comma", in: "dev.pyck.cloud,", wantErr: true},
		{name: "duplicate", in: "dev.pyck.cloud,DEV.pyck.cloud", wantErr: true},
		{name: "duplicate IP", in: "192.0.2.10,192.0.2.10", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseHosts(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseHosts(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			}

			if err != nil && !errors.Is(err, errHosts) {
				t.Errorf("error %v does not wrap errHosts", err)
			}

			if !slices.Equal(got, tc.want) {
				t.Errorf("ParseHosts(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
