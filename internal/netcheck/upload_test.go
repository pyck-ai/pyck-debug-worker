package netcheck

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pointUploadAt sends uploads to srv for the duration of the test.
func pointUploadAt(t *testing.T, srv *httptest.Server) {
	t.Helper()

	old := uploadURL
	uploadURL = srv.URL + "/upload"

	t.Cleanup(func() { uploadURL = old })
}

// finishedDay writes an old, finished day file and returns its path.
func finishedDay(t *testing.T, dir string) (string, []byte) {
	t.Helper()

	content := []byte(`{"type":"header"}` + "\n" + `{"type":"agg"}` + "\n")
	path := filepath.Join(dir, "2020-01-02.json")

	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	return path, content
}

func TestUploadSuccess(t *testing.T) {
	dir := t.TempDir()
	path, content := finishedDay(t, dir)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/upload" {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}

		if got := r.URL.Query().Get("name"); got != "box-netcheck-2020-01-02.json.gz" {
			t.Errorf("name = %q", got)
		}

		if got := r.URL.Query().Get("ref"); got != "box" {
			t.Errorf("ref = %q", got)
		}

		if r.ContentLength <= 0 || len(r.TransferEncoding) > 0 {
			t.Errorf("Content-Length %d, Transfer-Encoding %v: the receiver requires a length",
				r.ContentLength, r.TransferEncoding)
		}

		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Fatalf("body is not gzip: %v", err)
		}

		body, _ := io.ReadAll(zr)
		if !bytes.Equal(body, content) {
			t.Errorf("uploaded content = %q, want %q", body, content)
		}

		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"ok":true,"key":"uploads/box/x"}`)
	}))
	defer srv.Close()

	pointUploadAt(t, srv)

	var out bytes.Buffer

	ok := uploadPending(context.Background(), srv.Client(), newStore(dir, testHeader()), "box", &printer{out: &out})
	if !ok {
		t.Fatalf("upload failed: %s", out.String())
	}

	if _, err := os.Stat(path + sentExt); err != nil {
		t.Errorf("uploaded day not renamed to .sent: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("uploaded day still pending: %v", err)
	}

	if !strings.Contains(out.String(), "nc-upload") || !strings.Contains(out.String(), " ok ") {
		t.Errorf("no ok line: %q", out.String())
	}
}

func TestUploadFailureKeepsTheDay(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		detail string
	}{
		{name: "server error", status: http.StatusInternalServerError, body: `{}`, detail: "HTTP 500"},
		{name: "200 is not 201", status: http.StatusOK, body: `{"ok":true}`, detail: "HTTP 200"},
		{name: "ok false", status: http.StatusCreated, body: `{"ok":false}`, detail: "ok=false"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path, _ := finishedDay(t, dir)

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()

			pointUploadAt(t, srv)

			var out bytes.Buffer

			if uploadPending(context.Background(), srv.Client(), newStore(dir, testHeader()), "box", &printer{out: &out}) {
				t.Fatal("upload reported success")
			}

			if _, err := os.Stat(path); err != nil {
				t.Errorf("failed day no longer pending: %v", err)
			}

			if !strings.Contains(out.String(), "FAIL") || !strings.Contains(out.String(), tc.detail) {
				t.Errorf("line %q lacks FAIL and %q", out.String(), tc.detail)
			}
		})
	}
}
