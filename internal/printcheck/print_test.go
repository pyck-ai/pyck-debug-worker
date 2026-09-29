package printcheck

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// pointAt redirects base at srv for the duration of the test.
func pointAt(t *testing.T, base *string, srv *httptest.Server) {
	t.Helper()

	saved := *base
	*base = srv.URL + "/"

	t.Cleanup(func() { *base = saved })
}

// faxServer replies to every POST with ok and the fax_id reply returns.
func faxServer(t *testing.T, ok bool, faxID func(pathID string) string) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
			http.Error(w, "unexpected request", http.StatusBadRequest)

			return
		}

		_, _ = io.Copy(io.Discard, r.Body)

		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":        ok,
			"fax_id":    faxID(strings.TrimPrefix(r.URL.Path, "/")),
			"truncated": false,
		})
	}))
	t.Cleanup(srv.Close)

	return srv
}

func TestFaxStage(t *testing.T) {
	cfg := Config{Server: "print01.corp.example.com", Share: "Labels"}
	echo := func(id string) string { return id }

	t.Run("success", func(t *testing.T) {
		pointAt(t, &faxBaseURL, faxServer(t, true, echo))

		id, faxURL, result := faxStage(t.Context(), cfg, http.DefaultClient, []string{"a", "b"})
		if !result.OK {
			t.Fatalf("result = %+v, want OK", result)
		}

		if faxURL != faxBaseURL+id {
			t.Errorf("faxURL = %q, want %q", faxURL, faxBaseURL+id)
		}

		if want := "posted 6 bytes, 2 lines to " + faxURL; result.Detail != want {
			t.Errorf("detail = %q, want %q", result.Detail, want)
		}
	})

	t.Run("ok=false fails", func(t *testing.T) {
		pointAt(t, &faxBaseURL, faxServer(t, false, echo))

		if _, _, result := faxStage(t.Context(), cfg, http.DefaultClient, []string{"a"}); result.OK {
			t.Errorf("result = %+v, want a failure", result)
		}
	})

	t.Run("mismatched fax_id fails", func(t *testing.T) {
		pointAt(t, &faxBaseURL, faxServer(t, true, func(string) string { return "someone-else" }))

		if _, _, result := faxStage(t.Context(), cfg, http.DefaultClient, []string{"a"}); result.OK {
			t.Errorf("result = %+v, want a failure", result)
		}
	})
}

func TestZPLStage(t *testing.T) {
	cfg := Config{Server: "print01.corp.example.com", Share: "Labels"}
	faxURL := "https://fax.pyck.cloud/0f6c7c1e-8d0e-4b8a-9c55-2f1f6f0f5a11"

	serve := func(body string) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("format") != "zpl" {
				http.Error(w, "unexpected request", http.StatusBadRequest)

				return
			}

			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(srv.Close)

		return srv
	}

	t.Run("success", func(t *testing.T) {
		body := "^XA\n^PW200\n^LL200\n^FDMA," + faxURL + "^FS\n^XZ\n"
		pointAt(t, &barcodeBaseURL, serve(body))

		zpl, result := zplStage(t.Context(), cfg, http.DefaultClient, faxURL)
		if !result.OK {
			t.Fatalf("result = %+v, want OK", result)
		}

		if string(zpl) != body {
			t.Errorf("zpl = %q, want the body verbatim %q", zpl, body)
		}
	})

	t.Run("a body that is not ZPL fails", func(t *testing.T) {
		pointAt(t, &barcodeBaseURL, serve("<html>bad gateway</html>"))

		if _, result := zplStage(t.Context(), cfg, http.DefaultClient, faxURL); result.OK {
			t.Errorf("result = %+v, want a failure", result)
		}
	})
}
