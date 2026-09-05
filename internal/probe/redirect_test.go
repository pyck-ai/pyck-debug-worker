package probe

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// hostOf returns the hostname component of a test server URL.
func hostOf(t *testing.T, rawURL string) string {
	t.Helper()

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}

	return parsed.Hostname()
}

func TestCheckRedirect(t *testing.T) {
	tests := []struct {
		name string
		// handler answers the plaintext request. location is templated with
		// the server's own host so same-host cases are exact.
		handler  func(host string) http.HandlerFunc
		wantOK   bool
		contains []string
	}{
		{
			name: "308 to https on the same host",
			handler: func(host string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Location", "https://"+host+"/")
					w.WriteHeader(http.StatusPermanentRedirect)
				}
			},
			wantOK:   true,
			contains: []string{"308", "https://"},
		},
		{
			name: "301 to https on the same host is equally fine",
			handler: func(host string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Location", "https://"+host+"/")
					w.WriteHeader(http.StatusMovedPermanently)
				}
			},
			wantOK:   true,
			contains: []string{"301", "https://"},
		},
		{
			name: "redirect that stays plaintext",
			handler: func(host string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Location", "http://"+host+"/elsewhere")
					w.WriteHeader(http.StatusFound)
				}
			},
			wantOK:   false,
			contains: []string{"redirect stays plaintext"},
		},
		{
			name: "redirect to another host",
			handler: func(string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Location", "https://elsewhere.example/")
					w.WriteHeader(http.StatusFound)
				}
			},
			wantOK:   false,
			contains: []string{"redirect leaves"},
		},
		{
			name: "200 serves content in the clear",
			handler: func(string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("hello"))
				}
			},
			wantOK:   false,
			contains: []string{"200", "plaintext served in the clear"},
		},
		{
			name: "404 over plaintext is still plaintext",
			handler: func(string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantOK:   false,
			contains: []string{"404", "plaintext served in the clear"},
		},
		{
			name: "redirect without a Location header",
			handler: func(string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusFound)
				}
			},
			wantOK:   false,
			contains: []string{"no Location header"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var host string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tc.handler(host)(w, r)
			}))
			defer server.Close()

			host = hostOf(t, server.URL)

			ok, detail := checkRedirect(t.Context(), server.URL, host)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v (detail %q)", ok, tc.wantOK, detail)
			}

			for _, want := range tc.contains {
				if !strings.Contains(detail, want) {
					t.Errorf("detail %q does not contain %q", detail, want)
				}
			}
		})
	}
}

func TestCheckRedirectDoesNotFollow(t *testing.T) {
	followed := false

	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed = true

		w.WriteHeader(http.StatusOK)
	}))
	defer final.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", final.URL+"/")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	// The Location points at a plaintext host, so the verdict is a failure —
	// what matters here is that the prober never requested it.
	if _, detail := checkRedirect(t.Context(), server.URL, hostOf(t, server.URL)); detail == "" {
		t.Fatal("empty detail")
	}

	if followed {
		t.Error("the prober followed the redirect; CheckRedirect must stop it")
	}
}

func TestCheckRedirectConnectionRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed := server.URL

	server.Close()

	// Nothing listening on the plaintext port is a valid HTTPS-only setup.
	ok, detail := checkRedirect(t.Context(), closed, hostOf(t, closed))
	if !ok {
		t.Errorf("ok = false, want true (detail %q)", detail)
	}

	if !strings.Contains(detail, "connection refused") {
		t.Errorf("detail %q does not mention connection refused", detail)
	}
}

func TestRedirectVerdictIgnoresStatusCodeChoice(t *testing.T) {
	// 301 and 308 are both correct: Traefik's `permanent` is left at the chart
	// default, so the code itself must not be asserted.
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusPermanentRedirect} {
		resp := &http.Response{
			StatusCode: code,
			Status:     http.StatusText(code),
			Header:     http.Header{"Location": []string{"https://test.pyck.cloud/"}},
		}

		if ok, detail := redirectVerdict(resp, "test.pyck.cloud"); !ok {
			t.Errorf("code %d: ok = false, want true (detail %q)", code, detail)
		}
	}
}
