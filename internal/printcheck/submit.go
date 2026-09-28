package printcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/par/iremotewinspool/v1"
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
// what makes conn.Bind consult the endpoint mapper to resolve IRemoteWinspool's
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

// transportPAR and transportPipe name the two transports in the debug log, so
// a customer log shows which one carried a successful submit without needing
// the wire capture that established the distinction in the first place.
//
// The values stay protocol sequences, but the two constants name different
// interfaces as well as different wires: transportPAR is MS-PAR's
// IRemoteWinspool at PKT_PRIVACY over TCP, transportPipe is MS-RPRN's winspool
// at PKT_INTEGRITY over \pipe\spoolss. There is no winspool-over-TCP pairing
// any more; through v1.2.2 the TCP attempt bound winspool at sign, which is
// not a combination Windows serves, and the identifier was renamed so that
// nothing still reads as if it were.
const (
	transportPAR  = "ncacn_ip_tcp"
	transportPipe = "ncacn_np"
)

// printerAccessUse is PRINTER_ACCESS_USE (MS-RPRN §2.2.3.1): the right to
// submit a job. Nothing here asks for administrative access to the spooler.
const printerAccessUse = 0x00000008

// docInfoLevel1 selects the DOC_INFO_1 structure (MS-RPRN §2.2.1.4).
const docInfoLevel1 = 1

// splClientInfoLevel1 selects SPLCLIENT_INFO_1, the only level MS-RPRN allows
// in an SPLCLIENT_CONTAINER.
const splClientInfoLevel1 = 1

// splClientInfo1Size is SPLCLIENT_INFO_1's dwSize as Samba's spoolss client
// sends it: the structure's size in its 32-bit layout.
const splClientInfo1Size = 28

// datatypeText asks the spooler's text print processor to render the job, so
// the diagnostic lines come out as plain text rather than being interpreted as
// a printer control language.
const datatypeText = "TEXT"

// documentName is what shows up in the Windows print queue.
const documentName = "pyck-debug-worker cycle 1"

// errorSuccess is ERROR_SUCCESS, the only acceptable return from an RPRN call.
const errorSuccess = 0

// submitTimeout bounds the whole P5 ladder: the SMB dial, NEGOTIATE,
// SESSION_SETUP, the RPC bind, and the seven spooler calls. Against a healthy
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

// tcpDialTimeout bounds each TCP connect the TCP transport makes: the
// endpoint mapper's own dial to port 135, and the dial to the dynamic port it
// resolves. go-msrpc's own default is 10s (dcerpc/transport_settings.go); a
// port that is open answers the TCP handshake in milliseconds; one that is
// merely closed answers with an immediate RST. Only a firewall silently
// dropping the packets takes any real time at all to fail, and that pattern
// does not need 10s to be recognized — the whole TCP attempt runs before the
// pipe is even tried, and it should not eat most of the stage's submitTimeout
// budget doing so.
const tcpDialTimeout = 3 * time.Second

// submitStage performs P5: the real print job, over MS-PAR or, failing that,
// MS-RPRN.
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
			return false, submitDetail(debugLogger(), err)
		}

		return true, fmt.Sprintf("job %d spooled to %s: %d bytes, %d lines, datatype=%s",
			jobID, cfg.UNC(), len(payload), len(lines), datatypeText)
	})
}

// submitDetail splits a failed submit between the two streams.
//
// The raw errors go to the debug stream on stderr, one per line, each verbatim
// and unaccompanied: the operator asked for the libraries' own output, not for
// it to be explained, and this stage's errors nest two transports deep, so one
// flattened line is unreadable however it is punctuated. What comes back is
// the single line the result column holds, which is the taxonomy's verdict
// where there is one and the error's own top frame where there is not.
//
// The two streams rather than extra results: report.Run.Add tallies one n/m
// per Result, so a raw error line returned as a Result would count as a stage
// that ran and failed, and the cycle's "OK n/m" would report more stages than
// the ladder has. The debug stream is already where the libraries narrate, and
// after this release it renders in the same fixed-width shape as the result
// lines, so the two read as one log.
func submitDetail(logger zerolog.Logger, err error) string {
	lines := chainLines(err)

	for _, line := range lines {
		logger.Error().Msg(line)
	}

	if verdict := verdictOf(err); verdict != "" {
		return verdict
	}

	// No verdict: the top frame is the most specific thing that can honestly
	// be said, and the rest is already on the debug stream.
	if len(lines) > 0 {
		return lines[0]
	}

	return err.Error()
}

// Payload renders the cycle's lines as the job body. CRLF is the only
// transformation: the content is the diagnostic output verbatim.
func Payload(lines []string) []byte {
	if len(lines) == 0 {
		return nil
	}

	return []byte(strings.Join(lines, "\r\n") + "\r\n")
}

// submit binds the spooler and runs the seven-call job sequence over whichever
// interface the bind landed on: MS-PAR's RpcAsyncOpenPrinter …
// RpcAsyncClosePrinter over TCP, or MS-RPRN's RpcOpenPrinter … RpcClosePrinter
// over the named pipe.
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

	conn, parSpooler, pipeSpooler, transport, err := connect(security, cfg, krb5Config, logger)
	if err != nil {
		return 0, err
	}

	defer conn.Close(security)

	logger.Debug().Str("transport", transport).Msg("spooler bound")

	// Two job bodies rather than one behind an interface: MS-PAR and MS-RPRN
	// carry the same seven operations, but go-msrpc generates each interface
	// its own request, response and context-handle types, so a printer handle
	// from one is not even the same Go type as a handle from the other. A
	// shared abstraction over them would be an adapter layer written only to
	// be read past; two straight-line bodies are what a reader diffs against
	// a wire capture.
	if transport == transportPAR {
		return submitOverPAR(security, parSpooler, cfg, payload)
	}

	return submitOverPipe(security, pipeSpooler, cfg, payload)
}

// submitOverPipe runs the MS-RPRN sequence over the named pipe:
// RpcOpenPrinter, RpcStartDocPrinter, RpcStartPagePrinter, RpcWritePrinter,
// RpcEndPagePrinter, RpcEndDocPrinter, RpcClosePrinter. This is the job body
// the stage has always run, moved out of submit unchanged.
func submitOverPipe(
	security context.Context,
	spooler winspool.WinspoolClient,
	cfg Config,
	payload []byte,
) (uint32, error) {
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

// submitOverPAR runs the MS-PAR sequence over TCP: RpcAsyncOpenPrinter,
// RpcAsyncStartDocPrinter, RpcAsyncStartPagePrinter, RpcAsyncWritePrinter,
// RpcAsyncEndPagePrinter, RpcAsyncEndDocPrinter, RpcAsyncClosePrinter.
//
// It is submitOverPipe call for call. MS-PAR defines its job operations as the
// asynchronous counterparts of MS-RPRN's and reuses MS-RPRN's structures for
// their arguments, so the access mask, the DOC_INFO_1 level and the TEXT
// datatype mean exactly what they mean on the pipe. The errors name the
// RpcAsync operations because those are the opnums on the wire; a failure
// reported as RpcOpenPrinter here would send the reader to the wrong
// interface's documentation.
//
// RpcAsyncOpenPrinter takes two arguments RpcOpenPrinter does not. pDatatype
// is unique and left null, in which case the job's own DOC_INFO_1 datatype
// governs, as it does on the pipe. pClientInfo is not optional: it is a [ref]
// pointer to an SPLCLIENT_CONTAINER whose Level "MUST be 0x00000001" (MS-RPRN
// §2.2.1.2.14), and go-msrpc refuses to marshal the zero-value container
// (Level 0 is not a union arm), so leaving it empty fails the call locally
// before anything is sent. Only the size, machine and user are filled in; the
// build and version fields describe a Windows client and stay zero.
func submitOverPAR(
	security context.Context,
	spooler iremotewinspool.RemoteWinspoolClient,
	cfg Config,
	payload []byte,
) (uint32, error) {
	hostname, _ := os.Hostname()

	opened, err := spooler.OpenPrinter(security, &iremotewinspool.OpenPrinterRequest{
		PrinterName:      cfg.UNC(),
		DevModeContainer: &iremotewinspool.DevModeContainer{},
		AccessRequired:   printerAccessUse,
		ClientInfo: &iremotewinspool.ClientContainer{
			Level: splClientInfoLevel1,
			ClientInfo: &iremotewinspool.ClientContainer_ClientInfo{
				Value: &iremotewinspool.ClientContainer_ClientInfo_ClientInfo1{
					ClientInfo1: &iremotewinspool.ClientInfo1{
						Size:        splClientInfo1Size,
						MachineName: hostname,
						UserName:    cfg.User(),
					},
				},
			},
		},
	})
	if err != nil {
		return 0, fmt.Errorf("RpcAsyncOpenPrinter %s: %w", cfg.UNC(), err)
	}

	if err := returned("RpcAsyncOpenPrinter", opened.Return); err != nil {
		return 0, err
	}

	printer := opened.Handle

	// From here the printer handle is open; every path must close it.
	defer func() {
		_, _ = spooler.ClosePrinter(security, &iremotewinspool.ClosePrinterRequest{Printer: printer})
	}()

	started, err := spooler.StartDocPrinter(security, &iremotewinspool.StartDocPrinterRequest{
		Printer: printer,
		DocInfoContainer: &iremotewinspool.DocInfoContainer{
			Level: docInfoLevel1,
			DocInfo: &iremotewinspool.DocInfoContainer_DocInfo{
				Value: &iremotewinspool.DocInfoContainer_DocInfo1{
					DocInfo1: &iremotewinspool.DocInfo1{
						DocName:  documentName,
						DataType: datatypeText,
					},
				},
			},
		},
	})
	if err != nil {
		return 0, fmt.Errorf("RpcAsyncStartDocPrinter: %w", err)
	}

	if err := returned("RpcAsyncStartDocPrinter", started.Return); err != nil {
		return 0, err
	}

	page, err := spooler.StartPagePrinter(security, &iremotewinspool.StartPagePrinterRequest{Printer: printer})
	if err != nil {
		return started.JobID, fmt.Errorf("RpcAsyncStartPagePrinter: %w", err)
	}

	if err := returned("RpcAsyncStartPagePrinter", page.Return); err != nil {
		return started.JobID, err
	}

	written, err := spooler.WritePrinter(security, &iremotewinspool.WritePrinterRequest{
		Printer:      printer,
		Buffer:       payload,
		BufferLength: uint32(len(payload)),
	})
	if err != nil {
		return started.JobID, fmt.Errorf("RpcAsyncWritePrinter: %w", err)
	}

	if err := returned("RpcAsyncWritePrinter", written.Return); err != nil {
		return started.JobID, err
	}

	if int(written.WrittenCount) != len(payload) {
		return started.JobID, fmt.Errorf(
			"RpcAsyncWritePrinter accepted %d of %d bytes: the job would print truncated",
			written.WrittenCount, len(payload))
	}

	endPage, err := spooler.EndPagePrinter(security, &iremotewinspool.EndPagePrinterRequest{Printer: printer})
	if err != nil {
		return started.JobID, fmt.Errorf("RpcAsyncEndPagePrinter: %w", err)
	}

	if err := returned("RpcAsyncEndPagePrinter", endPage.Return); err != nil {
		return started.JobID, err
	}

	endDoc, err := spooler.EndDocPrinter(security, &iremotewinspool.EndDocPrinterRequest{Printer: printer})
	if err != nil {
		return started.JobID, fmt.Errorf("RpcAsyncEndDocPrinter: %w", err)
	}

	if err := returned("RpcAsyncEndDocPrinter", endDoc.Return); err != nil {
		return started.JobID, err
	}

	return started.JobID, nil
}

// connect binds the spooler over whichever transport the server actually
// offers, and reports which one that was. Exactly one of the two returned
// clients is non-nil, and the returned transport says which.
//
// MS-PAR over TCP is tried first because it is what Windows clients speak
// first. A Windows client does not run MS-RPRN over TCP at all: over TCP it
// binds a different interface, MS-PAR's IRemoteWinspool, at
// RPC_C_AUTHN_LEVEL_PKT_PRIVACY, and only if that fails does it fall back to
// MS-RPRN over \pipe\spoolss (MS-PAR Appendix B, note <38>: Vista and later
// try MS-PAR first). Since Windows 11 22H2 the named pipe is off by default
// unless a policy re-enables it, which is why the pipe's CREATE returns
// STATUS_OBJECT_NAME_NOT_FOUND on a current server that is otherwise
// authenticating and sharing the printer correctly — MS-PAR is then the only
// way in.
//
// Through v1.2.2 the TCP attempt bound MS-RPRN's winspool interface at sign
// instead. That is not a path Windows serves, and a server answers it the way
// it answers any bind below the interface's required authentication level: the
// first call, RpcOpenPrinter, faults in the RPC runtime with status 5. That
// reads like the spooler refusing the printer, but the spooler never saw the
// call.
//
// The pipe is kept as the fallback rather than dropped, because it remains the
// path on Server 2016/2019/2022 and on any newer server where the policy has
// re-enabled it, and it is what a Windows client falls back to as well.
// Neither transport is configured or selected by this side: both are
// attempted, in that order, on every run.
func connect(
	security context.Context,
	cfg Config,
	krb5Config *krb5.Config,
	logger zerolog.Logger,
) (dcerpc.Conn, iremotewinspool.RemoteWinspoolClient, winspool.WinspoolClient, string, error) {
	conn, parSpooler, err := connectPAR(security, cfg, krb5Config, logger)
	if err == nil {
		return conn, parSpooler, nil, transportPAR, nil
	}

	// Not a failure of the stage: on a server that does not offer MS-PAR over
	// TCP this is the expected outcome, and the pipe below is the working path.
	logger.Debug().Err(err).Msg("ms-par over tcp unavailable, falling back to the named pipe")

	conn, pipeSpooler, pipeErr := connectPipe(security, cfg, krb5Config, logger)
	if pipeErr != nil {
		// Both transports are reported, and both stay unwrappable. Either
		// error alone invites the wrong conclusion: the TCP error alone reads
		// as a firewall problem, and the pipe error alone reads as a missing
		// printer. Until v1.2.0 the second was folded in with %v, which
		// flattened its chain into the first's text and left the operator one
		// line with the other transport's errors nested in parentheses;
		// errors.Join keeps them as two chains that chainLines can walk
		// separately. The pipe is named first because it is the transport the
		// ladder ended on.
		return nil, nil, nil, "", errors.Join(
			fmt.Errorf("%s: %w", transportPipe, pipeErr),
			fmt.Errorf("%s: %w", transportPAR, err),
		)
	}

	return conn, nil, pipeSpooler, transportPipe, nil
}

// connectPAR binds MS-PAR's IRemoteWinspool over ncacn_ip_tcp, resolving its
// dynamic port through the endpoint mapper on port 135. The interface itself
// is not named here: NewRemoteWinspoolClient adds its abstract syntax to the
// bind, the same way NewWinspoolClient does for the pipe.
//
// The authentication moves with the transport. There is no SMB session here,
// so the Kerberos exchange that the pipe path performs during SMB session
// setup happens in the RPC bind instead: WithSecurityConfig carries the same
// krb5 config — and so the same bounded KDC dialer — into the bind's own
// security context, and WithTargetName supplies the SPN that gssapi.WithTargetName
// supplies on the SMB side.
//
// Every option set asks for seal, not sign. MS-PAR requires
// RPC_C_AUTHN_LEVEL_PKT_PRIVACY (MS-PAR §2.1), and a bind below it is refused
// by the RPC runtime before the spooler sees a single call. The pipe stays at
// sign: that is the level MS-RPRN over \pipe\spoolss has been working at since
// v1.1.5, and that path is deliberately left untouched. The endpoint mapper's
// lookup is sealed as well, so this attempt carries one authentication level
// from port 135 onward rather than two.
func connectPAR(
	security context.Context,
	cfg Config,
	krb5Config *krb5.Config,
	logger zerolog.Logger,
) (dcerpc.Conn, iremotewinspool.RemoteWinspoolClient, error) {
	targetName := tcpServiceClass + "/" + cfg.Server

	// Unlike the named pipe's, this Dial does open a socket: epm.EndpointMapper
	// connects to port 135 while constructing the mapper, so a server that is
	// unreachable or not running an endpoint mapper fails here rather than at
	// Bind. tcpDialTimeout is passed to both: the mapper's own dial to 135,
	// and — since it is a ConnectOption, read off t.settings.Timeout for the
	// net.DialTimeout call in dcerpc/conn.go — the dial to whatever dynamic
	// port the mapper resolves.
	conn, err := dcerpc.Dial(security, cfg.Server,
		epm.EndpointMapper(security, cfg.Server,
			dcerpc.WithSeal(),
			dcerpc.WithTargetName(targetName),
			dcerpc.WithSecurityConfig(krb5Config),
			dcerpc.WithLogger(logger),
			dcerpc.WithTimeout(tcpDialTimeout),
		),
		dcerpc.WithEndpoint(tcpEndpoint),
		dcerpc.WithSeal(),
		dcerpc.WithTargetName(targetName),
		dcerpc.WithSecurityConfig(krb5Config),
		dcerpc.WithLogger(logger),
		dcerpc.WithTimeout(tcpDialTimeout),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", tcpEndpoint, err)
	}

	spooler, err := iremotewinspool.NewRemoteWinspoolClient(security, conn,
		dcerpc.WithSeal(),
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

		return nil, nil, fmt.Errorf("bind spooler over %s: %w", transportPAR, err)
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

// debugComponent labels the stream in its own column, so a journal that
// interleaves it with the result lines still attributes each line.
const debugComponent = "print-submit"

// debugComponentW and debugLevelW are the widths of the two fixed columns the
// debug stream carries between its timestamp and its message. The component is
// sized to its only content; the level is four to match the width the result
// lines give their own ok/FAIL status column, which puts the same two-space
// gap in front of the message that every other column boundary has.
const (
	debugComponentW = len(debugComponent)
	debugLevelW     = 4
)

// debugLogger is the DCE/RPC stack's debug log. It goes to stderr so it stays
// out of the result lines on stdout, and it renders in the same fixed-width
// shape those lines use rather than in JSON:
//
//	<ts>  <component>  <lvl>  <message>  <key>=<value> …
//
// The timestamp column matches report.Result.Line exactly — same layout, same
// UTC — so both streams line up when journalctl shows them together. Colour is
// off because the destination is journald, where ANSI escapes are noise.
func debugLogger() zerolog.Logger {
	writer := zerolog.ConsoleWriter{
		Out:     os.Stderr,
		NoColor: true,
		// zerolog re-parses its own timestamp before formatting, and does so
		// in TimeLocation — so UTC has to be named here, or the local zone
		// would render (the JSON stream's +02:00 in the customer log is
		// exactly that).
		TimeFormat:   report.TSLayout,
		TimeLocation: time.UTC,
		// The component is promoted to a part so it renders as a column, and
		// excluded from the trailing fields so it is not also repeated as
		// component=print-submit on all forty lines.
		PartsOrder: []string{
			zerolog.TimestampFieldName,
			componentField,
			zerolog.LevelFieldName,
			zerolog.MessageFieldName,
		},
		FieldsExclude: []string{componentField},
		FormatPartValueByName: func(value any, name string) string {
			if name != componentField {
				return fmt.Sprintf("%s", value)
			}

			return fmt.Sprintf(" %-*s", debugComponentW, value)
		},
		// zerolog's own level formatter colourises and abbreviates to three;
		// this one only pads, to the same width the result lines give their
		// status column.
		FormatLevel: func(value any) string {
			level := strings.ToUpper(fmt.Sprintf("%s", value))
			if len(level) > debugLevelW {
				level = level[:debugLevelW]
			}

			return fmt.Sprintf(" %-*s", debugLevelW, level)
		},
		FormatFieldName:  func(value any) string { return fmt.Sprintf("%s=", value) },
		FormatFieldValue: func(value any) string { return fmt.Sprintf("%s", value) },
	}

	return zerolog.New(writer).
		With().
		Timestamp().
		Str(componentField, debugComponent).
		Logger().
		Level(zerolog.DebugLevel)
}

// componentField is the key the component travels under. It is a part name as
// well as a field name, which is why it is a constant rather than a literal in
// both places.
const componentField = "component"

// returned turns a non-zero MS-RPRN return code into an error. The spooler
// reports failures in the return value, not only in the RPC fault, so a call
// that "succeeded" with a non-zero code has still not printed anything.
func returned(call string, code uint32) error {
	if code == errorSuccess {
		return nil
	}

	return fmt.Errorf("%s returned Win32 error %d (0x%08x)", call, code, code)
}
