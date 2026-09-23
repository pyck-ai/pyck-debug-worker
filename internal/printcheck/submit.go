package printcheck

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
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

// spoolssEndpoint is the well-known named pipe MS-RPRN is bound to. It is
// fixed by the protocol (idl/rprn.idl: endpoint("ncacn_np:[\\pipe\\spoolss]")),
// so the endpoint mapper is not consulted.
const spoolssEndpoint = `ncacn_np:[\pipe\spoolss]`

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

	// go-msrpc narrates the ladder this stage is opaque about — "dialing smb
	// named pipe", "found established transport", "binding the selected
	// transport" — but only at debug level, so the level is lowered
	// explicitly. dcerpc.Dial itself opens no socket: it records the options
	// and the connection is established inside the Bind below, which is why
	// the logger is passed to both.
	logger := debugLogger()

	conn, err := dcerpc.Dial(security, cfg.Server,
		dcerpc.WithSMBDialer(dialer),
		dcerpc.WithEndpoint(spoolssEndpoint),
		dcerpc.WithSign(),
		dcerpc.WithLogger(logger),
	)
	if err != nil {
		return 0, fmt.Errorf("dial %s: %w", spoolssEndpoint, err)
	}

	defer conn.Close(security)

	spooler, err := winspool.NewWinspoolClient(security, conn, dcerpc.WithSign(), dcerpc.WithLogger(logger))
	if err != nil {
		return 0, fmt.Errorf("bind spooler: %w", err)
	}

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
