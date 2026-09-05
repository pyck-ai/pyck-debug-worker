// Package buildinfo carries the values stamped into the binary at link time.
//
// Only the version and the commit are stamped. There is deliberately no build
// date: a timestamp destroys bit-for-bit reproducibility, and -buildvcs already
// records everything else worth knowing.
package buildinfo

// Version is the release version, set via
// -ldflags="-X github.com/pyck-ai/pyck-debug-worker/internal/buildinfo.Version=v1.2.3".
var Version = "dev"

// Commit is the git commit the binary was built from, set via
// -ldflags="-X github.com/pyck-ai/pyck-debug-worker/internal/buildinfo.Commit=abc1234".
var Commit = "none"

// String renders the stamped build identity as "<version> (<commit>)".
func String() string {
	return Version + " (" + Commit + ")"
}
