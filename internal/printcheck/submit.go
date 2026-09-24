package printcheck

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/rprn/winspool/v1"
	"github.com/oiweiwei/go-msrpc/smb2"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/oiweiwei/go-msrpc/ssp/krb5"
	"github.com/rs/zerolog"

	"github.com/pyck-ai/pyck-debug-worker/internal/report"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

// spoolssEndpoint is the named pipe MS-RPRN's spec binds the interface to
// (idl/rprn.idl: endpoint("ncacn_np:[\\pipe\\spoolss]")). It is a fixed
// endpoint, so the endpoint mapper is not consulted for it.
const spoolssEndpoint = `ncacn_np:[\pipe\spoolss]`

// tcpEndpoint selects the TCP protocol sequence without naming a port. The
// port is left empty deliberately: the binding is then incomplete
// (dcerpc/binding.go Complete reports false while Endpoint is ""), which is
// what makes conn.Bind consult the endpoint mapper to resolve winspool's
// dynamic port, rather than dialing a port this side guessed. Naming the
// protocol sequence at all is what keeps the mapper's reply filtered to TCP:
// epm's Map appends the well-known named-pipe binding to every lookup result,
// and without this filter that pipe would be dialed as a silent fallback
// inside the TCP attempt, which would make the two transports
// indistinguishable in the logs.
const tcpEndpoint = "ncacn_ip_tcp:"

// tcpServiceClass is the SPN service class for the TCP transport. The named
// pipe authenticates against the SMB service (cifs/), because its RPC rides
// on an SMB session; over TCP there is no SMB session and the RPC bind
// authenticates against the machine itself. Every domain-joined computer
// registers HOST/<name> at domain join, so this needs nothing configured on
// the server.
const tcpServiceClass = "host"

// transportTCP and transportPipe name the two transports in the debug log, so
// a customer log shows which one carried a successful submit without needing
// the wire capture that established the distinction in the first place.
const (
	transportTCP  = "ncacn_ip_tcp"
	transportPipe = "ncacn_np"
)

// printerAccessUse is PRINTER_ACCESS_USE (MS-RPRN §2.2.3.1): the right to
// submit a job. Nothing here asks for administrative access to the spooler.
const printerAccessUse = 0x00000008

// docInfoLevel1 selects the DOC_INFO_1 structure (MS-RPRN §2.2.1.4).
const docInfoLevel1 = 1

// datatypeText asks the spooler's text print processor to render the job, so
// the diagnostic lines come out as plain text rather than being interpreted as
// a printer control language.
const datatypeText = "TEXT"

// documentName is what shows up in the Windows print queue.
const documentName = "pyck-debug-worker cycle 1"

// errorSuccess is ERROR_SUCCESS, the only acceptable return from an RPRN call.
const errorSuccess = 0

// submitTimeout bounds the whole P5 ladder: the SMB dial, NEGOTIATE,
// SESSION_SETUP, the RPC bind, and the seven RPRN calls. Against a healthy
// server all of it completes in well under a second — P3 and P4 do the same
// dial and the same session setup in the same run and report sub-100ms
// durations, and P5's extra work is seven round trips on an already-open pipe.
// Anything still running at 20s is stuck rather than slow, and the loop that
// calls this runs the print check synchronously, so an unbounded stall blocks
// every subsequent probe cycle behind it.
const submitTimeout = 20 * time.Second

// kdcTimeout bounds a single KDC dial inside go-msrpc's own Kerberos client.
// That client is a second, independent one: P1 has already logged in with
// gokrb5/v8 by the time this stage runs, and go-msrpc's Kerberos SSP goes back
// to the KDC for its own AS-REQ/TGS-REQ regardless. gokrb5.fork's default dial
// timeout is five minutes (client/settings.go Dialer), so one silently dropped
// packet on the way to a KDC stalls the whole stage for minutes — and
// submitTimeout does not bound it, because go-msrpc builds that security
// context with a literal context.Background() (smb2/initiator.go) and so never
// sees the deadline this stage sets.
//
// Five seconds is what P1 already allows per KDC (gokrb5/v8
// client/network.go), and on the healthy path P1 proves the KDC answers in
// milliseconds. A KDC that has not answered in five seconds is not going to.
const kdcTimeout = 5 * time.Second

// submitStage performs P5: the real MS-RPRN job.
//
// Authentication branch — go-msrpc's own client, end to end. Its Kerberos SSP
// accepts a keytab credential natively (ssp/credential/keytab.go
// NewFromKeytabFile, consumed at ssp/krb5/authentifier.go as
// `case credential.Keytab: cli.Credentials = creds.WithKeytab(...)`), so the
// fallback of layering its wire stubs over our own session is not needed. Only
// the KRB5 mechanism is registered: no SPNEGO negotiation, no NTLM, no
// password path exists in this process.
func submitStage(ctx context.Context, cfg Config, lines []string) report.Result {
	return stage(cfg, "submit", func() (bool, string) {
		payload := Payload(lines)

		submitCtx, cancel := context.WithTimeout(ctx, submitTimeout)
		defer cancel()

		jobID, err := submit(submitCtx, cfg, payload)
		if err != nil {
			return false, classify(err)
		}

		return true, fmt.Sprintf("job %d spooled to %s: %d bytes, %d lines, datatype=%s",
			jobID, cfg.UNC(), len(payload), len(lines), datatypeText)
	})
}

// Payload renders the cycle's lines as the job body. CRLF is the only
// transformation: the content is the diagnostic output verbatim.
func Payload(lines []string) []byte {
	if len(lines) == 0 {
		return nil
	}

	return []byte(strings.Join(lines, "\r\n") + "\r\n")
}

// submit runs the MS-RPRN sequence: RpcOpenPrinter, RpcStartDocPrinter,
// RpcStartPagePrinter, RpcWritePrinter, RpcEndPagePrinter, RpcEndDocPrinter,
// RpcClosePrinter.
func submit(ctx context.Context, cfg Config, payload []byte) (uint32, error) {
	security := gssapi.NewSecurityContext(ctx)

	gssapi.AddCredential(credential.NewFromKeytabFile(cfg.Principal, cfg.Keytab))

	// SMB session setup carries an SPNEGO-wrapped token, so SPNEGO is
	// registered as the negotiation wrapper — but Kerberos is the only
	// mechanism inside it. NTLM is never registered, so there is no NTLM code
	// path in this process to fall back to, and no password mechanism either.
	gssapi.AddMechanism(ssp.SPNEGO)
	gssapi.AddMechanism(ssp.KRB5)

	// The Kerberos config is go-msrpc's own, started from its NewConfig so the
	// DCEStyle, DisablePAFXFAST and AnyServiceClassSPN defaults it needs
	// against Active Directory are kept; only the KDC dialer is replaced, to
	// put a bound on the dial that would otherwise stall for five minutes.
	krb5Config := krb5.NewConfig()
	krb5Config.KDCDialer = &net.Dialer{Timeout: kdcTimeout}

	// go-msrpc narrates the ladder this stage is opaque about — "dialing smb
	// named pipe", "found established transport", "binding the selected
	// transport" — but only at debug level, so the level is lowered
	// explicitly. dcerpc.Dial itself opens no socket for the named pipe: it
	// records the options and the connection is established inside the Bind,
	// which is why the logger is passed to both.
	logger := debugLogger()

	conn, spooler, transport, err := connect(security, cfg, krb5Config, logger)
	if err != nil {
		return 0, err
	}

	defer conn.Close(security)

	logger.Debug().Str("transport", transport).Msg("spooler bound")

	opened, err := spooler.OpenPrinter(security, &winspool.OpenPrinterRequest{
		PrinterName:      cfg.UNC(),
		DevModeContainer: &winspool.DevModeContainer{},
		AccessRequired:   printerAccessUse,
	})
	if err != nil {
		return 0, fmt.Errorf("RpcOpenPrinter %s: %w", cfg.UNC(), err)
	}

	if err := returned("RpcOpenPrinter", opened.Return); err != nil {
		return 0, err
	}

	printer := opened.Handle

	// From here the printer handle is open; every path must close it.
	defer func() {
		_, _ = spooler.ClosePrinter(security, &winspool.ClosePrinterRequest{Printer: printer})
	}()

	started, err := spooler.StartDocPrinter(security, &winspool.StartDocPrinterRequest{
		Printer: printer,
		DocInfoContainer: &winspool.DocInfoContainer{
			Level: docInfoLevel1,
			DocInfo: &winspool.DocInfoContainer_DocInfo{
				Value: &winspool.DocInfoContainer_DocInfo1{
					DocInfo1: &winspool.DocInfo1{
						DocName:  documentName,
						DataType: datatypeText,
					},
				},
			},
		},
	})
	if err != nil {
		return 0, fmt.Errorf("RpcStartDocPrinter: %w", err)
	}

	if err := returned("RpcStartDocPrinter", started.Return); err != nil {
		return 0, err
	}

	page, err := spooler.StartPagePrinter(security, &winspool.StartPagePrinterRequest{Printer: printer})
	if err != nil {
		return started.JobID, fmt.Errorf("RpcStartPagePrinter: %w", err)
	}

	if err := returned("RpcStartPagePrinter", page.Return); err != nil {
		return started.JobID, err
	}

	written, err := spooler.WritePrinter(security, &winspool.WritePrinterRequest{
		Printer:      printer,
		Buffer:       payload,
		BufferLength: uint32(len(payload)),
	})
	if err != nil {
		return started.JobID, fmt.Errorf("RpcWritePrinter: %w", err)
	}

	if err := returned("RpcWritePrinter", written.Return); err != nil {
		return started.JobID, err
	}

	if int(written.WrittenCount) != len(payload) {
		return started.JobID, fmt.Errorf(
			"RpcWritePrinter accepted %d of %d bytes: the job would print truncated",
			written.WrittenCount, len(payload))
	}

	endPage, err := spooler.EndPagePrinter(security, &winspool.EndPagePrinterRequest{Printer: printer})
	if err != nil {
		return started.JobID, fmt.Errorf("RpcEndPagePrinter: %w", err)
	}

	if err := returned("RpcEndPagePrinter", endPage.Return); err != nil {
		return started.JobID, err
	}

	endDoc, err := spooler.EndDocPrinter(security, &winspool.EndDocPrinterRequest{Printer: printer})
	if err != nil {
		return started.JobID, fmt.Errorf("RpcEndDocPrinter: %w", err)
	}

	if err := returned("RpcEndDocPrinter", endDoc.Return); err != nil {
		return started.JobID, err
	}

	return started.JobID, nil
}

// connect binds the spooler over whichever transport the server actually
// offers, and reports which one that was.
//
// TCP is tried first because it is what current Windows listens on. MS-RPRN's
// spec still documents only the named pipe (MS-RPRN §2.1), but the shipping OS
// has moved past its own spec: since Windows 11 22H2 the spooler listens on
// RPC over TCP by default and the named pipe is off unless a policy re-enables
// it, which is why the pipe's CREATE returns
// STATUS_OBJECT_NAME_NOT_FOUND on a current server that is otherwise
// authenticating and sharing the printer correctly.
//
// The pipe is kept as the fallback rather than dropped, because it remains the
// only transport on Server 2016/2019/2022 and on any newer server where the
// policy has re-enabled it. Neither transport is configured or selected by
// this side: both are attempted, in that order, on every run.
func connect(
	security context.Context,
	cfg Config,
	krb5Config *krb5.Config,
	logger zerolog.Logger,
) (dcerpc.Conn, winspool.WinspoolClient, string, error) {
	conn, spooler, err := connectTCP(security, cfg, krb5Config, logger)
	if err == nil {
		return conn, spooler, transportTCP, nil
	}

	// Not a failure of the stage: on a server predating the transport change
	// this is the expected outcome, and the pipe below is the working path.
	logger.Debug().Err(err).Msg("rpc over tcp unavailable, falling back to the named pipe")

	conn, spooler, pipeErr := connectPipe(security, cfg, krb5Config, logger)
	if pipeErr != nil {
		// Both transports are reported. Either error alone invites the wrong
		// conclusion: the TCP error alone reads as a firewall problem, and the
		// pipe error alone reads as a missing printer.
		return nil, nil, "", fmt.Errorf("%s: %w (%s: %v)", transportPipe, pipeErr, transportTCP, err)
	}

	return conn, spooler, transportPipe, nil
}

// connectTCP binds the spooler over ncacn_ip_tcp, resolving winspool's dynamic
// port through the endpoint mapper on port 135.
//
// The authentication moves with the transport. There is no SMB session here,
// so the Kerberos exchange that the pipe path performs during SMB session
// setup happens in the RPC bind instead: WithSecurityConfig carries the same
// krb5 config — and so the same bounded KDC dialer — into the bind's own
// security context, and WithTargetName supplies the SPN that gssapi.WithTargetName
// supplies on the SMB side.
func connectTCP(
	security context.Context,
	cfg Config,
	krb5Config *krb5.Config,
	logger zerolog.Logger,
) (dcerpc.Conn, winspool.WinspoolClient, error) {
	targetName := tcpServiceClass + "/" + cfg.Server

	// Unlike the named pipe's, this Dial does open a socket: epm.EndpointMapper
	// connects to port 135 while constructing the mapper, so a server that is
	// unreachable or not running an endpoint mapper fails here rather than at
	// Bind.
	conn, err := dcerpc.Dial(security, cfg.Server,
		epm.EndpointMapper(security, cfg.Server,
			dcerpc.WithSign(),
			dcerpc.WithTargetName(targetName),
			dcerpc.WithSecurityConfig(krb5Config),
			dcerpc.WithLogger(logger),
		),
		dcerpc.WithEndpoint(tcpEndpoint),
		dcerpc.WithSign(),
		dcerpc.WithTargetName(targetName),
		dcerpc.WithSecurityConfig(krb5Config),
		dcerpc.WithLogger(logger),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", tcpEndpoint, err)
	}

	spooler, err := winspool.NewWinspoolClient(security, conn,
		dcerpc.WithSign(),
		dcerpc.WithTargetName(targetName),
		dcerpc.WithSecurityConfig(krb5Config),
		dcerpc.WithLogger(logger),
	)
	if err != nil {
		// The connection is closed here rather than left to the caller: the
		// caller only defers Close for the transport it went on to use, and a
		// half-established one would otherwise hold its socket for the rest of
		// the run.
		_ = conn.Close(security)

		return nil, nil, fmt.Errorf("bind spooler over %s: %w", transportTCP, err)
	}

	return conn, spooler, nil
}

// connectPipe binds the spooler over ncacn_np, the transport MS-RPRN's spec
// documents. This is the v1.1.5 path, unchanged: the SMB dialer carries the
// Kerberos exchange in the session setup, and the endpoint is fixed by the
// protocol rather than resolved.
func connectPipe(
	security context.Context,
	cfg Config,
	krb5Config *krb5.Config,
	logger zerolog.Logger,
) (dcerpc.Conn, winspool.WinspoolClient, error) {
	// The mechanism type is pinned to SPNEGO explicitly. Supplying any
	// mechanism config makes gssapi adopt that mechanism's OID as the
	// context's mechanism type when none was set (gssapi.WithMechanismConfig),
	// which would select raw Kerberos instead of SPNEGO for the session setup
	// token — a different wire format than the one that works today. Pinning
	// it keeps SPNEGO as the wrapper and leaves the config to be picked up by
	// the Kerberos mechanism inside it.
	dialer := smb2.NewDialer(smb2.WithSecurity(
		gssapi.WithTargetName(cfg.SPN()),
		gssapi.WithMechanismType(ssp.MechanismTypeSPNEGO),
		ssp.WithKRB5(krb5Config),
	))

	conn, err := dcerpc.Dial(security, cfg.Server,
		dcerpc.WithSMBDialer(dialer),
		dcerpc.WithEndpoint(spoolssEndpoint),
		dcerpc.WithSign(),
		dcerpc.WithLogger(logger),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", spoolssEndpoint, err)
	}

	spooler, err := winspool.NewWinspoolClient(security, conn, dcerpc.WithSign(), dcerpc.WithLogger(logger))
	if err != nil {
		_ = conn.Close(security)

		return nil, nil, fmt.Errorf("bind spooler: %w", err)
	}

	return conn, spooler, nil
}

// debugLogger is the DCE/RPC stack's debug log. It goes to stderr so it stays
// out of the result lines on stdout, and carries a component field so its
// output is distinguishable from them at a glance.
func debugLogger() zerolog.Logger {
	return zerolog.New(os.Stderr).
		With().
		Timestamp().
		Str("component", "print-submit").
		Logger().
		Level(zerolog.DebugLevel)
}

// returned turns a non-zero MS-RPRN return code into an error. The spooler
// reports failures in the return value, not only in the RPC fault, so a call
// that "succeeded" with a non-zero code has still not printed anything.
func returned(call string, code uint32) error {
	if code == errorSuccess {
		return nil
	}

	return fmt.Errorf("%s returned Win32 error %d (0x%08x)", call, code, code)
}
