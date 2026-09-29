package printcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cloudsoda/go-smb2"
	"github.com/google/uuid"

	"github.com/pyck-ai/pyck-debug-worker/internal/report"
)

// faxBaseURL and barcodeBaseURL are the two pyck services the print check
// talks to. They are hardcoded like every other endpoint this binary knows;
// they are variables rather than constants only so the tests can point them
// at an httptest server.
var (
	faxBaseURL     = "https://fax.pyck.cloud/"
	barcodeBaseURL = "https://barcodes.pyck.cloud/barcode/qr/"
)

// httpTimeout bounds each of the two HTTP stages end to end. Both services
// answer a request this size in milliseconds; ten seconds is stuck, not slow.
const httpTimeout = 10 * time.Second

// spoolTimeout bounds the SMB write. The print check runs synchronously ahead
// of every later probe cycle, so a stalled write must not hold the loop; a
// label this size spools in milliseconds against a healthy server.
const spoolTimeout = 20 * time.Second

// faxReply is the fax service's acknowledgement. Only the fields the stage
// checks are decoded.
type faxReply struct {
	OK        bool   `json:"ok"`
	FaxID     string `json:"fax_id"`
	Truncated bool   `json:"truncated"`
}

// Payload renders the cycle's lines as the fax body. CRLF is the only
// transformation: the content is the diagnostic output verbatim.
func Payload(lines []string) []byte {
	if len(lines) == 0 {
		return nil
	}

	return []byte(strings.Join(lines, "\r\n") + "\r\n")
}

// faxStage posts the first cycle's lines to the fax service under a fresh ID
// and returns that ID and the URL the lines now live at.
//
// A 200 alone is not taken as success: the service reports truncation and its
// own verdict in the body, and it echoes the ID back, so a reply for a
// different fax — a cache or a proxy answering in the service's place — is
// caught here rather than printed as a QR code that opens the wrong page.
func faxStage(ctx context.Context, cfg Config, httpClient *http.Client, lines []string) (string, string, report.Result) {
	id := uuid.NewString()
	faxURL := faxBaseURL + id

	result := stage(cfg, "fax", func() (bool, string) {
		payload := Payload(lines)

		request, err := http.NewRequestWithContext(ctx, http.MethodPost, faxURL, bytes.NewReader(payload))
		if err != nil {
			return false, classify(err)
		}

		request.Header.Set("Content-Type", "text/plain; charset=utf-8")

		response, err := httpClient.Do(request)
		if err != nil {
			return false, classify(err)
		}

		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			return false, fmt.Sprintf("%s: HTTP %s", faxURL, response.Status)
		}

		var reply faxReply
		if err := json.NewDecoder(response.Body).Decode(&reply); err != nil {
			return false, faxURL + ": undecodable reply: " + err.Error()
		}

		switch {
		case !reply.OK:
			return false, faxURL + ": service replied ok=false"
		case reply.FaxID != id:
			return false, fmt.Sprintf("%s: reply names fax %q, not %q", faxURL, reply.FaxID, id)
		case reply.Truncated:
			return false, fmt.Sprintf("%s: service truncated the %d-byte payload", faxURL, len(payload))
		}

		return true, fmt.Sprintf("posted %d bytes, %d lines to %s", len(payload), len(lines), faxURL)
	})

	return id, faxURL, result
}

// zplStage fetches a QR code for faxURL, already rendered as ZPL.
//
// ZPL is what the label printer executes natively, so the bytes need no
// driver and no rendering on the print server: whatever lands in the share
// is passed through to the printer as-is. That is also why the body is
// checked for the ^XA…^XZ frame before it is spooled — anything else (an
// error page, an empty body) would be printed as garbage or not at all, with
// the spooler reporting success either way.
func zplStage(ctx context.Context, cfg Config, httpClient *http.Client, faxURL string) ([]byte, report.Result) {
	var zpl []byte

	result := stage(cfg, "zpl", func() (bool, string) {
		barcodeURL := barcodeBaseURL + url.PathEscape(faxURL) + "?format=zpl"

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, barcodeURL, nil)
		if err != nil {
			return false, classify(err)
		}

		response, err := httpClient.Do(request)
		if err != nil {
			return false, classify(err)
		}

		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			return false, fmt.Sprintf("%s: HTTP %s", barcodeURL, response.Status)
		}

		body, err := io.ReadAll(response.Body)
		if err != nil {
			return false, classify(err)
		}

		trimmed := strings.TrimSpace(string(body))
		if !strings.HasPrefix(trimmed, "^XA") || !strings.HasSuffix(trimmed, "^XZ") {
			return false, fmt.Sprintf("%s: %d-byte body is not a ^XA…^XZ ZPL label", barcodeURL, len(body))
		}

		zpl = body

		return true, fmt.Sprintf("%d bytes of ZPL, QR -> %s", len(zpl), faxURL)
	})

	return zpl, result
}

// spoolStage writes the ZPL into the printer share over the SMB session P3
// already established.
//
// A Windows printer share accepts a file write as a raw print job: the
// server's spooler takes the bytes and hands them to the printer untouched,
// which is exactly what `smbclient -c 'print file'` does. So this needs no
// spooler RPC interface, no second connection, and no second Kerberos client:
// the session that P3 authenticated is the credential the job rides on.
//
// The Close error is checked, not dropped: the write only fills the spool
// file, and it is at Close that the spooler takes it as a job.
func spoolStage(ctx context.Context, cfg Config, session *smb2.Session, id, faxURL string, zpl []byte) report.Result {
	return stage(cfg, "submit", func() (bool, string) {
		spoolCtx, cancel := context.WithTimeout(ctx, spoolTimeout)
		defer cancel()

		// The full UNC, not the bare share name: given a bare name, go-smb2
		// prefixes the address the session was dialed with, host:445, so the
		// tree connect would name the server with a port. Windows accepts
		// that (P4's IPC$ mount goes out the same way), but \\host\share is
		// what smbclient sends, and this stage should match the one command
		// already proven to print on the customer's server.
		share, err := session.Mount(cfg.UNC())
		if err != nil {
			return false, cfg.UNC() + ": " + classify(err)
		}

		// Mount's share does not inherit any context; without this the
		// create, write and close would be unbounded.
		share = share.WithContext(spoolCtx)

		defer func() { _ = share.Umount() }()

		file, err := share.Create("pyck-debug-worker-" + id + ".zpl")
		if err != nil {
			return false, cfg.UNC() + ": " + classify(err)
		}

		written, err := file.Write(zpl)
		if err != nil {
			_ = file.Close()

			return false, cfg.UNC() + ": " + classify(err)
		}

		if written != len(zpl) {
			_ = file.Close()

			return false, fmt.Sprintf("%s accepted %d of %d bytes: the label would print truncated",
				cfg.UNC(), written, len(zpl))
		}

		if err := file.Close(); err != nil {
			return false, cfg.UNC() + ": " + classify(err)
		}

		return true, fmt.Sprintf("%d bytes of ZPL spooled to %s, QR -> %s", len(zpl), cfg.UNC(), faxURL)
	})
}
