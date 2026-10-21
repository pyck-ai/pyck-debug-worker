package netcheck

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

// uploadURL is the debug-dropbox receiver. A variable only so the tests can
// point it at an httptest server.
var uploadURL = "https://debug.pyck.cloud/upload"

// Upload timing.
const (
	// uploadRetry is the wait after a failed upload.
	uploadRetry = time.Hour
	// uploadAfterMidnight is how long after UTC midnight a finished day is
	// sent, leaving the last minute's flush time to land.
	uploadAfterMidnight = time.Minute
	// uploadTimeout bounds one upload end to end.
	uploadTimeout = 2 * time.Minute
)

// uploadReply is the receiver's acknowledgement.
type uploadReply struct {
	OK  bool   `json:"ok"`
	Key string `json:"key"`
}

// uploadLoop sends every finished, unsent day at startup and after each UTC
// midnight; after a failure it retries hourly.
func uploadLoop(ctx context.Context, store *store, hostname string, p *printer) {
	client := &http.Client{Timeout: uploadTimeout}

	for {
		wait := untilAfterMidnight(time.Now())
		if !uploadPending(ctx, client, store, hostname, p) {
			wait = uploadRetry
		}

		if !sleep(ctx, wait) {
			return
		}
	}
}

// untilAfterMidnight is the wait until uploadAfterMidnight past the next UTC
// midnight.
func untilAfterMidnight(now time.Time) time.Duration {
	next := now.UTC().Truncate(24 * time.Hour).Add(24*time.Hour + uploadAfterMidnight)

	return next.Sub(now)
}

// uploadPending uploads every finished day and reports whether all of them
// went through.
func uploadPending(ctx context.Context, client *http.Client, store *store, hostname string, p *printer) bool {
	paths, err := store.finished(time.Now())
	if err != nil {
		p.line(time.Now(), store.dir, "nc-upload", false, 0, err.Error())

		return false
	}

	allOK := true

	for _, path := range paths {
		started := time.Now()
		ok, detail := uploadDay(ctx, client, path, hostname)

		if ctx.Err() != nil {
			return false
		}

		p.line(started, receiver(), "nc-upload", ok, time.Since(started), detail)

		allOK = allOK && ok
	}

	return allOK
}

// uploadDay gzips one day file, posts it and, on success, renames it to
// .sent. Success is HTTP 201 with ok:true; the body is fully buffered so the
// request carries a Content-Length, which the receiver requires.
func uploadDay(ctx context.Context, client *http.Client, path, hostname string) (bool, string) {
	raw, err := os.ReadFile(path) //nolint:gosec // path comes from the store's own glob
	if err != nil {
		return false, err.Error()
	}

	var body bytes.Buffer

	zw := gzip.NewWriter(&body)
	if _, err := zw.Write(raw); err != nil {
		return false, err.Error()
	}

	if err := zw.Close(); err != nil {
		return false, err.Error()
	}

	name := fmt.Sprintf("%s-netcheck-%s.json.gz", hostname, dayOf(path))
	query := url.Values{"name": {name}, "ref": {hostname}}
	endpoint := uploadURL + "?" + query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body.Bytes()))
	if err != nil {
		return false, err.Error()
	}

	request.Header.Set("Content-Type", "application/gzip")

	response, err := client.Do(request)
	if err != nil {
		return false, err.Error()
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		return false, fmt.Sprintf("%s: HTTP %s", name, response.Status)
	}

	var reply uploadReply
	if err := json.NewDecoder(response.Body).Decode(&reply); err != nil {
		return false, name + ": undecodable reply: " + err.Error()
	}

	if !reply.OK {
		return false, name + ": receiver replied ok=false"
	}

	if err := os.Rename(path, path+sentExt); err != nil {
		return false, fmt.Sprintf("%s uploaded as %s, but: %v", name, reply.Key, err)
	}

	return true, fmt.Sprintf("posted %d bytes (%d gzipped) as %s, key %s", len(raw), body.Len(), name, reply.Key)
}

// receiver is the upload host, for the stdout target column.
func receiver() string {
	if u, err := url.Parse(uploadURL); err == nil {
		return u.Host
	}

	return uploadURL
}
