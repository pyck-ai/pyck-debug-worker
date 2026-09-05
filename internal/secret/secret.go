// Package secret holds credentials that must never reach a log line, an error
// string or a serialised struct.
//
// Secret is a struct with an unexported field rather than a defined string
// type: a defined string type is still convertible back to string and still
// prints itself under %s, so it protects nothing. Every method has a value
// receiver, because encoding/json silently ignores pointer-receiver marshalers
// on a value field — a Secret embedded by value in a config struct would then
// serialise in the clear.
package secret

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strconv"
)

// fingerprintBytes is how much of the digest is shown. Enough to tell two
// credentials apart, far too little to attack.
const fingerprintBytes = 4

// unsetText is the rendering of a Secret that holds nothing. Hashing the empty
// string would print a plausible-looking fingerprint for a credential that is
// not there, which is exactly the kind of lie this tool must not tell.
const unsetText = "<unset>"

// Secret is a credential that redacts itself in every rendering path.
type Secret struct {
	value string
}

// New wraps a credential.
func New(value string) Secret {
	return Secret{value: value}
}

// Reveal returns the credential. It is the only accessor, so
// `grep -rn '\.Reveal()'` is a complete audit of where the secret escapes.
func (s Secret) Reveal() string {
	return s.value
}

// IsZero reports whether no credential is held. It is the gate for stages that
// require one.
func (s Secret) IsZero() bool {
	return s.value == ""
}

// String implements fmt.Stringer.
func (s Secret) String() string {
	if s.value == "" {
		return unsetText
	}

	sum := sha256.Sum256([]byte(s.value))

	return "sha256:" + hex.EncodeToString(sum[:fingerprintBytes]) +
		"…(len=" + strconv.Itoa(len(s.value)) + ")"
}

// GoString implements fmt.GoStringer, covering %#v.
func (s Secret) GoString() string {
	return s.String()
}

// Format implements fmt.Formatter. It is the critical one: fmt consults
// Formatter before Stringer, GoStringer and any verb-specific handling, so
// %q, %x and %#v cannot reach the underlying value.
func (s Secret) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, s.String())
}

// MarshalJSON implements json.Marshaler.
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(s.String())), nil
}

// MarshalText implements encoding.TextMarshaler.
func (s Secret) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// LogValue implements slog.LogValuer.
func (s Secret) LogValue() slog.Value {
	return slog.StringValue(s.String())
}
