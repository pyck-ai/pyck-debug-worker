package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// theSecret is the credential every test tries, and fails, to print.
const theSecret = "pat_super_secret_value_0123456789"

func TestRedactedInEveryVerb(t *testing.T) {
	s := New(theSecret)

	// %#v is rendered through a config struct: a Secret sitting in a larger
	// value is the way it actually reaches a log line.
	type config struct {
		Token Secret
		Env   string
	}

	tests := []struct {
		name   string
		render func() string
	}{
		{name: "%v", render: func() string { return fmt.Sprintf("%v", s) }},
		{name: "%s", render: func() string { return fmt.Sprintf("%s", s) }},
		{name: "%q", render: func() string { return fmt.Sprintf("%q", s) }},
		{name: "%x", render: func() string { return fmt.Sprintf("%x", s) }},
		{name: "%X", render: func() string { return fmt.Sprintf("%X", s) }},
		{name: "%d", render: func() string { return fmt.Sprintf("%d", s) }},
		{name: "%#v", render: func() string { return fmt.Sprintf("%#v", s) }},
		{name: "%+v", render: func() string { return fmt.Sprintf("%+v", s) }},
		{name: "print", render: func() string { return fmt.Sprint(s) }},
		{name: "stringer", render: func() string { return s.String() }},
		{name: "gostringer", render: func() string { return s.GoString() }},
		{name: "struct %v", render: func() string { return fmt.Sprintf("%v", config{Token: s, Env: "test"}) }},
		{name: "struct %#v", render: func() string { return fmt.Sprintf("%#v", config{Token: s, Env: "test"}) }},
		{name: "struct %+v", render: func() string { return fmt.Sprintf("%+v", config{Token: s, Env: "test"}) }},
		{
			name: "pointer to struct",
			render: func() string {
				return fmt.Sprintf("%v", &config{Token: s, Env: "test"})
			},
		},
		{
			name: "json",
			render: func() string {
				b, err := json.Marshal(config{Token: s, Env: "test"})
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}

				return string(b)
			},
		},
		{
			name: "text marshaler",
			render: func() string {
				b, err := s.MarshalText()
				if err != nil {
					t.Fatalf("marshal text: %v", err)
				}

				return string(b)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.render()
			if strings.Contains(got, theSecret) {
				t.Fatalf("rendering leaked the secret: %s", got)
			}

			if !strings.Contains(got, "sha256:") {
				t.Errorf("rendering %q carries no fingerprint", got)
			}
		})
	}
}

func TestSlogRedacts(t *testing.T) {
	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("probe", "token", New(theSecret))

	if strings.Contains(buf.String(), theSecret) {
		t.Fatalf("slog leaked the secret: %s", buf.String())
	}

	if !strings.Contains(buf.String(), "sha256:") {
		t.Errorf("slog output carries no fingerprint: %s", buf.String())
	}
}

func TestFingerprintIsStableAndDistinct(t *testing.T) {
	a := New(theSecret)
	b := New(theSecret)
	c := New(theSecret + "x")

	if a.String() != b.String() {
		t.Errorf("same secret rendered differently: %q vs %q", a, b)
	}

	if a.String() == c.String() {
		t.Errorf("different secrets rendered identically: %q", a)
	}

	if want := fmt.Sprintf("(len=%d)", len(theSecret)); !strings.HasSuffix(a.String(), want) {
		t.Errorf("%q does not end with %q", a.String(), want)
	}
}

func TestReveal(t *testing.T) {
	if got := New(theSecret).Reveal(); got != theSecret {
		t.Errorf("Reveal() = %q, want the credential back", got)
	}
}

func TestZeroValue(t *testing.T) {
	var s Secret

	if !s.IsZero() {
		t.Error("IsZero() = false on the zero value")
	}

	if got := s.String(); got != unsetText {
		t.Errorf("String() = %q, want %q: an absent credential must not look present", got, unsetText)
	}

	if New(theSecret).IsZero() {
		t.Error("IsZero() = true for a held credential")
	}
}
