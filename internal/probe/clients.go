package probe

import (
	"crypto/tls"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/pyck-ai/pyck-debug-worker/internal/target"
)

// Clients holds the gRPC connections that outlive a single cycle.
//
// The channels are deliberately reused: how a connection recovers — idle,
// transient failure, back to ready — is itself the signal, and dialling fresh
// every cycle would throw that history away. DNS, TCP and TLS are rebuilt every
// cycle instead, which is what those stages are for.
//
// main owns the cache and closes it once on shutdown.
type Clients struct {
	mu       sync.Mutex
	conns    map[string]*grpc.ClientConn
	temporal map[string]*temporalClient
	logger   *sdkLogger
	longpoll *poller
}

// NewClients returns an empty connection cache.
func NewClients() *Clients {
	return &Clients{
		conns:    map[string]*grpc.ClientConn{},
		temporal: map[string]*temporalClient{},
		logger:   &sdkLogger{},
	}
}

// grpcConn returns the cached connection for a target, creating it on first
// use. The second return reports whether this call created it.
//
// grpc.NewClient performs no I/O, so creating a connection here proves nothing
// about reachability; the caller establishes that from the connectivity state.
func (c *Clients) grpcConn(tgt target.Target, opts Options) (*grpc.ClientConn, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if conn, ok := c.conns[tgt.Addr()]; ok {
		return conn, false, nil
	}

	creds := credentials.NewTLS(&tls.Config{
		ServerName: tgt.Host,
		RootCAs:    opts.Roots,
		MinVersion: tls.VersionTLS12,
	})

	if opts.Insecure {
		creds = insecure.NewCredentials()
	}

	// grpc.Dial and WithBlock are deprecated. NewClient defaults to the dns
	// resolver where Dial used passthrough, so the scheme is explicit.
	conn, err := grpc.NewClient("dns:///"+tgt.Addr(), grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, false, err
	}

	c.conns[tgt.Addr()] = conn

	return conn, true, nil
}

// temporalClient returns the cached Temporal client for a target and
// namespace, creating it on first use.
//
// NewLazyClient is used rather than Dial: Dial performs an eager health check,
// and this tool measures that reachability itself in a stage named after it
// rather than having it happen invisibly at construction.
func (c *Clients) temporalClient(tgt target.Target, opts Options, namespace string) (*temporalClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := tgt.Addr() + "|" + namespace
	if cached, ok := c.temporal[key]; ok {
		return cached, nil
	}

	options := client.Options{
		HostPort:  tgt.Addr(),
		Namespace: namespace,
		Identity:  probeIdentity(),
		Logger:    c.logger,
	}

	if !opts.APIKey.IsZero() {
		options.Credentials = client.NewAPIKeyStaticCredentials(opts.APIKey.Reveal())
	}

	// API-key credentials switch TLS on inside the SDK, so the plaintext
	// in-cluster path has to switch it back off explicitly or it breaks.
	if opts.Insecure {
		options.ConnectionOptions.TLSDisabled = true
	}

	created, err := client.NewLazyClient(options)
	if err != nil {
		return nil, err
	}

	wrapped := &temporalClient{client: created}
	c.temporal[key] = wrapped

	return wrapped, nil
}

// poller returns the single long-poll worker, starting it on first use.
//
// One worker for the whole run, never one per cycle: a worker restarted every
// 30s would never hold a poll long enough to observe what this stage exists to
// observe.
func (c *Clients) poller(tgt target.Target, opts Options) (*poller, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.longpoll != nil {
		return c.longpoll, nil
	}

	if err := ValidateTaskQueue(opts.TaskQueue); err != nil {
		return nil, err
	}

	cached, ok := c.temporal[tgt.Addr()+"|"+effectiveNamespace(opts)]
	if !ok {
		return nil, fmt.Errorf("%w: no Temporal client for %s", ErrTaskQueue, tgt.Addr())
	}

	identity := probeIdentity()

	w := worker.New(cached.client, opts.TaskQueue, worker.Options{Identity: identity})
	w.RegisterWorkflow(probeWorkflow)

	if err := w.Start(); err != nil {
		return nil, err
	}

	c.longpoll = &poller{
		client:   cached.client,
		worker:   w,
		logger:   c.logger,
		identity: identity,
		queue:    opts.TaskQueue,
		started:  time.Now(),
	}

	return c.longpoll, nil
}

// probeIdentity is how this process names itself to Temporal, so the longpoll
// stage can pick its own poller out of the list.
func probeIdentity() string {
	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}

	return "pyck-debug-worker@" + host + "@" + strconv.Itoa(os.Getpid())
}

// Close drains the worker and closes every cached connection.
func (c *Clients) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.longpoll != nil {
		c.longpoll.stop()
		c.longpoll = nil
	}

	for key, temporal := range c.temporal {
		temporal.client.Close()

		delete(c.temporal, key)
	}

	for addr, conn := range c.conns {
		_ = conn.Close()

		delete(c.conns, addr)
	}
}
