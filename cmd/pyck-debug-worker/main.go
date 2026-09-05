// Command pyck-debug-worker probes pyck endpoints on a fixed interval and
// reports, per stage, whether they are reachable.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pyck-ai/pyck-debug-worker/internal/buildinfo"
	"github.com/pyck-ai/pyck-debug-worker/internal/probe"
	"github.com/pyck-ai/pyck-debug-worker/internal/report"
	"github.com/pyck-ai/pyck-debug-worker/internal/secret"
	"github.com/pyck-ai/pyck-debug-worker/internal/target"
)

// Process exit codes.
const (
	// exitOK means every cycle was clean.
	exitOK = 0
	// exitFailure means at least one cycle contained a failure.
	exitFailure = 1
	// exitUsage means a config or usage error, including a rejected
	// secret-bearing flag.
	exitUsage = 2
)

// Everything below is intentionally not a flag. This binary probes fixed pyck
// infrastructure on a fixed cadence; the only real questions are "which
// environment" and "what version is this" — --env and --version. Every other
// knob (interval, in-cluster mode, deep long-poll, task queue, CA bundle,
// resolver tracing, explicit host targets) is a hardcoded, safe default so
// there is nothing left to misconfigure.
const (
	// hardcodedInterval is the cycle period.
	hardcodedInterval = 30 * time.Second
	// cycleTimeout bounds one cycle so a hung probe cannot stall the next tick.
	cycleTimeout = 25 * time.Second
	// jitterDivisor sets the jitter window to interval/jitterDivisor.
	jitterDivisor = 10
	// hardcodedTaskQueue is the dedicated queue used by the longpoll stage. It
	// is never a real queue, so no live workflow task is ever stolen.
	hardcodedTaskQueue = "pyck-debug-worker-probe"
	// hardcodedDeep enables the long-poll stage. It is gated by TEMPORAL_API_KEY
	// regardless, so turning it on unconditionally is safe.
	hardcodedDeep = true
	// maxConcurrentTargets bounds how many targets are probed at once.
	maxConcurrentTargets = 8
)

// Environment variables read for credentials and identity. Secrets never come
// from argv: /proc/<pid>/cmdline is world-readable.
const (
	envAPIToken     = "PYCK_API_TOKEN"
	envServiceToken = "PYCK_SERVICE_TOKEN"
	envAuth         = "PYCK_AUTH"
	envTenantID     = "PYCK_API_TENANT_ID"
	envGatewayURL   = "PYCK_GATEWAY_URL"
	envNamespace    = "TEMPORAL_NAMESPACE"
	envAPIKey       = "TEMPORAL_API_KEY"
)

// tokenEnvVars is the precedence order for a pyck credential.
var tokenEnvVars = []string{envAPIToken, envServiceToken, envAuth}

// errUsage marks an error that should exit with exitUsage.
var errUsage = errors.New("usage")

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main's testable body.
func run(args []string, stdout, stderr io.Writer) int {
	if err := rejectSecretArgs(args); err != nil {
		fmt.Fprintln(stderr, err)

		return exitUsage
	}

	// Defense in depth: the queue is a hardcoded constant, not user input, but
	// validating it once at the door costs nothing and guards against a future
	// edit to the constant introducing a real queue name by mistake.
	if err := probe.ValidateTaskQueue(hardcodedTaskQueue); err != nil {
		panic(fmt.Sprintf("hardcodedTaskQueue is invalid: %v", err))
	}

	cfg, err := parseFlags(args, stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, err)
		}

		return exitUsage
	}

	if cfg.version {
		fmt.Fprintln(stdout, buildinfo.String())

		return exitOK
	}

	targets, err := cfg.resolveTargets()
	if err != nil {
		fmt.Fprintln(stderr, err)

		if len(cfg.envs) == 0 {
			cfg.fs.SetOutput(stderr)
			cfg.fs.Usage()
		}

		return exitUsage
	}

	creds, err := cfg.load()
	if err != nil {
		fmt.Fprintln(stderr, err)

		return exitUsage
	}

	banner(stdout, targets, creds)

	return loop(targets, creds, stdout)
}

// stringList collects a repeatable flag.
type stringList []string

// String implements flag.Value.
func (l *stringList) String() string {
	return strings.Join(*l, ",")
}

// Set implements flag.Value.
func (l *stringList) Set(v string) error {
	*l = append(*l, v)

	return nil
}

// config is the parsed command line.
type config struct {
	envs      stringList
	version   bool
	tokenFile string
	fs        *flag.FlagSet
}

// secretFlags are flag names that would put a credential in argv.
// /proc/<pid>/cmdline is mode 0444 on every mainstream distro and container
// image, so argv is world-readable.
var secretFlags = []string{"token", "api-key"}

// rejectSecretArgs fails on any attempt to pass a credential on the command
// line.
func rejectSecretArgs(args []string) error {
	for _, arg := range args {
		name, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")

		for _, bad := range secretFlags {
			if name != bad {
				continue
			}

			return fmt.Errorf(
				"%w: --%s is refused: argv is world-readable via /proc/<pid>/cmdline. "+
					"Pass credentials in the environment or with --token-file",
				errUsage, bad)
		}
	}

	return nil
}

// parseFlags parses args into a config. Only --env and --version select
// behavior; --token-file is the one credential-input flag, kept alongside the
// environment-variable precedence in load(). Everything else is hardcoded.
func parseFlags(args []string, stderr io.Writer) (*config, error) {
	cfg := &config{}

	fs := flag.NewFlagSet("pyck-debug-worker", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.Var(&cfg.envs, "env", "environment to probe (repeatable): local, dev, test, demo, prod, feature/<branch>")
	fs.StringVar(&cfg.tokenFile, "token-file", "", "path to a file holding a credential")
	fs.BoolVar(&cfg.version, "version", false, "print version and exit")

	cfg.fs = fs

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if fs.NArg() > 0 {
		return nil, fmt.Errorf("%w: unexpected argument %q", errUsage, fs.Arg(0))
	}

	return cfg, nil
}

// resolveTargets expands --env into the probe set, rejecting anything on the
// denylist.
func (c *config) resolveTargets() ([]target.Target, error) {
	if c.version {
		return nil, nil
	}

	var (
		targets []target.Target
		seen    = map[string]bool{}
	)

	for _, env := range c.envs {
		resolved, err := target.Resolve(env)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errUsage, err)
		}

		for _, t := range resolved {
			if seen[t.Addr()] {
				continue
			}

			seen[t.Addr()] = true
			targets = append(targets, t)
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("%w: nothing to probe: pass --env", errUsage)
	}

	for _, t := range targets {
		if denied, reason := target.Denied(t.Host, ""); denied {
			return nil, fmt.Errorf("%w: %s is never probed: %s", errUsage, t.Host, reason)
		}
	}

	return targets, nil
}

// credentials is everything the auth and tenant stages need. An empty token
// gates both of them off.
type credentials struct {
	token secret.Secret
	// source names where the credential came from. It is a variable name or a
	// flag name, never a value.
	source     string
	gatewayURL string
	tenantID   string
	namespace  string
	// apiKey is TEMPORAL_API_KEY.
	apiKey secret.Secret
}

// load reads the credential from --token-file or the environment. An explicit
// flag beats an ambient variable; otherwise the first non-empty variable wins
// in declaration order.
func (c *config) load() (credentials, error) {
	creds := credentials{
		gatewayURL: os.Getenv(envGatewayURL),
		tenantID:   os.Getenv(envTenantID),
		namespace:  os.Getenv(envNamespace),
		apiKey:     secret.New(os.Getenv(envAPIKey)),
	}

	if c.tokenFile != "" {
		raw, err := os.ReadFile(c.tokenFile)
		if err != nil {
			return credentials{}, fmt.Errorf("%w: --token-file: %w", errUsage, err)
		}

		token := strings.TrimSpace(string(raw))
		if token == "" {
			return credentials{}, fmt.Errorf("%w: --token-file: %s is empty", errUsage, c.tokenFile)
		}

		creds.token = secret.New(token)
		creds.source = "--token-file"

		return creds, nil
	}

	for _, name := range tokenEnvVars {
		if value := os.Getenv(name); value != "" {
			creds.token = secret.New(value)
			creds.source = name

			break
		}
	}

	return creds, nil
}

// banner prints the effective configuration. Absent credentials are never
// mentioned.
func banner(w io.Writer, targets []target.Target, creds credentials) {
	fmt.Fprintf(w, "pyck-debug-worker %s\n", buildinfo.String())
	fmt.Fprintf(w, "interval %s  cycle timeout %s  task-queue %s\n",
		hardcodedInterval, cycleTimeout, hardcodedTaskQueue)

	for _, t := range targets {
		fmt.Fprintf(w, "target %s %s\n", t.Addr(), t.Kind)
	}

	var opts []string

	// Only credentials that are actually present are named, and only ever by
	// their source. An absent one is not mentioned at all.
	if !creds.token.IsZero() {
		opts = append(opts, "token "+creds.source)
	}

	if !creds.apiKey.IsZero() {
		opts = append(opts, "api-key "+envAPIKey)
	}

	if creds.gatewayURL != "" {
		opts = append(opts, "gateway "+creds.gatewayURL)
	}

	if creds.tenantID != "" {
		opts = append(opts, envTenantID+" "+creds.tenantID)
	}

	if creds.namespace != "" {
		opts = append(opts, envNamespace+" "+creds.namespace)
	}

	if len(opts) > 0 {
		fmt.Fprintf(w, "options %s\n", strings.Join(opts, "  "))
	}
}

// loop runs cycles until SIGINT/SIGTERM, then prints the run summary.
func loop(targets []target.Target, creds credentials, out io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	labels := make([]string, 0, len(targets))
	for _, t := range targets {
		labels = append(labels, t.Addr())
	}

	// The gRPC channels outlive the cycles: how a connection recovers is
	// itself signal, and a fresh dial every cycle would erase it.
	clients := probe.NewClients()
	defer clients.Close()

	started := time.Now()
	run := report.NewRun(started, labels)

	ticker := time.NewTicker(hardcodedInterval)
	defer ticker.Stop()

	for n := 1; ; n++ {
		fmt.Fprintln(out, run.Add(cycle(ctx, n, targets, labels, out, probe.Options{
			Clients:           clients,
			Token:             creds.token,
			GatewayURL:        creds.gatewayURL,
			ExpectedTenantID:  creds.tenantID,
			TemporalNamespace: creds.namespace,
			APIKey:            creds.apiKey,
			Deep:              hardcodedDeep,
			TaskQueue:         hardcodedTaskQueue,
		})))

		select {
		case <-ctx.Done():
		case <-ticker.C:
			if sleepJitter(ctx, hardcodedInterval) {
				continue
			}
		}

		break
	}

	fmt.Fprintln(out, run.Summary(time.Now()))

	if run.Failed() {
		return exitFailure
	}

	return exitOK
}

// cycle runs one probe cycle under a fresh timeout and prints its result lines.
func cycle(ctx context.Context, n int, targets []target.Target, labels []string, out io.Writer, opts probe.Options) report.Cycle {
	ctx, cancel := context.WithTimeout(ctx, cycleTimeout)
	defer cancel()

	started := time.Now()
	results := probeTargets(ctx, targets, opts)

	for _, r := range results {
		fmt.Fprintln(out, r.Line())
	}

	return report.Cycle{
		N:        n,
		At:       started.UTC(),
		Duration: time.Since(started),
		Targets:  labels,
		Results:  results,
	}
}

// probeTargets runs the probe ladder over every target and returns one Result
// per stage that ran.
//
// Targets are probed concurrently under a bounded semaphore, but the results
// are reassembled in target order so the output stays grouped per target and in
// ladder order instead of being interleaved by completion time.
func probeTargets(ctx context.Context, targets []target.Target, opts probe.Options) []report.Result {
	perTarget := make([][]report.Result, len(targets))
	slots := make(chan struct{}, maxConcurrentTargets)

	var wg sync.WaitGroup

	for i, t := range targets {
		wg.Add(1)

		go func() {
			defer wg.Done()

			slots <- struct{}{}
			defer func() { <-slots }()

			perTarget[i] = probe.Run(ctx, t, opts)
		}()
	}

	wg.Wait()

	var results []report.Result

	for _, r := range perTarget {
		results = append(results, r...)
	}

	return results
}

// sleepJitter waits out the jitter window. It reports false if the context was
// cancelled while waiting.
func sleepJitter(ctx context.Context, interval time.Duration) bool {
	window := interval / jitterDivisor
	if window <= 0 {
		return ctx.Err() == nil
	}

	timer := time.NewTimer(rand.N(window))
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
