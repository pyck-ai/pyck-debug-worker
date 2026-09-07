package printcheck

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// envMap turns a map into the getenv function Load takes.
func envMap(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

// writableKeytab creates a readable stand-in keytab. Its contents are never
// parsed by Validate, only its readability is.
func writableKeytab(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "krb5-keytab")
	if err := os.WriteFile(path, []byte("not a real keytab"), 0o600); err != nil {
		t.Fatalf("write keytab: %v", err)
	}

	return path
}

func TestLoad(t *testing.T) {
	t.Run("explicit values win", func(t *testing.T) {
		got := Load(envMap(map[string]string{
			EnvServer:               "print01.corp.example.com",
			EnvShare:                "Reception",
			EnvPrincipal:            "svc-probe@CORP.EXAMPLE.COM",
			EnvKeytab:               "/etc/pyck/svc.keytab",
			EnvKrb5Conf:             "/etc/pyck/krb5.conf",
			envCredentialsDirectory: "/run/credentials/unit",
		}))

		want := Config{
			Server:    "print01.corp.example.com",
			Share:     "Reception",
			Principal: "svc-probe@CORP.EXAMPLE.COM",
			Keytab:    "/etc/pyck/svc.keytab",
			Krb5Conf:  "/etc/pyck/krb5.conf",
		}

		if got != want {
			t.Errorf("Load() = %+v, want %+v", got, want)
		}
	})

	t.Run("keytab defaults to the systemd credential", func(t *testing.T) {
		got := Load(envMap(map[string]string{
			envCredentialsDirectory: "/run/credentials/pyck-debug-worker@test.service",
		}))

		want := "/run/credentials/pyck-debug-worker@test.service/krb5-keytab"
		if got.Keytab != want {
			t.Errorf("Keytab = %q, want %q", got.Keytab, want)
		}
	})

	t.Run("krb5.conf defaults to the system path", func(t *testing.T) {
		if got := Load(envMap(nil)); got.Krb5Conf != defaultKrb5Conf {
			t.Errorf("Krb5Conf = %q, want %q", got.Krb5Conf, defaultKrb5Conf)
		}
	})

	t.Run("surrounding whitespace is not part of a hostname", func(t *testing.T) {
		got := Load(envMap(map[string]string{EnvServer: "  print01.corp.example.com\n"}))
		if got.Server != "print01.corp.example.com" {
			t.Errorf("Server = %q", got.Server)
		}
	})
}

func TestValidate(t *testing.T) {
	keytab := writableKeytab(t)

	valid := Config{
		Server:    "print01.corp.example.com",
		Share:     "Reception",
		Principal: "svc-probe@CORP.EXAMPLE.COM",
		Keytab:    keytab,
		Krb5Conf:  defaultKrb5Conf,
	}

	tests := []struct {
		name string
		// mutate turns the valid config into the case under test.
		mutate   func(Config) Config
		wantOK   bool
		contains []string
	}{
		{name: "complete", mutate: func(c Config) Config { return c }, wantOK: true},
		{
			name:     "server unset",
			mutate:   func(c Config) Config { c.Server = ""; return c },
			contains: []string{EnvServer + " is unset"},
		},
		{
			// Kerberos derives the SPN from a name; an address has none.
			name:     "server is an IP",
			mutate:   func(c Config) Config { c.Server = "10.1.2.3"; return c },
			contains: []string{"is an IP address"},
		},
		{
			name:     "server is a short name",
			mutate:   func(c Config) Config { c.Server = "print01"; return c },
			contains: []string{"is a short name"},
		},
		{
			name:     "share unset",
			mutate:   func(c Config) Config { c.Share = ""; return c },
			contains: []string{EnvShare + " is unset"},
		},
		{
			name:     "principal unset",
			mutate:   func(c Config) Config { c.Principal = ""; return c },
			contains: []string{EnvPrincipal + " is unset"},
		},
		{
			name:     "principal with an empty realm",
			mutate:   func(c Config) Config { c.Principal = "svc-probe@"; return c },
			contains: []string{"empty realm"},
		},
		{
			name:     "principal with no user",
			mutate:   func(c Config) Config { c.Principal = "@CORP.EXAMPLE.COM"; return c },
			contains: []string{"no user part"},
		},
		{
			name:     "principal with two realms",
			mutate:   func(c Config) Config { c.Principal = "svc@A@B"; return c },
			contains: []string{"more than one @"},
		},
		{
			name:     "keytab missing",
			mutate:   func(c Config) Config { c.Keytab = "/nonexistent/krb5-keytab"; return c },
			contains: []string{"is unreadable"},
		},
		{
			name:     "keytab unset with no credentials directory",
			mutate:   func(c Config) Config { c.Keytab = ""; return c },
			contains: []string{EnvKeytab + " is unset"},
		},
		{
			// One failed start should tell the operator everything that is
			// wrong, not one item per attempt.
			name: "every fault is reported at once",
			mutate: func(c Config) Config {
				c.Server = ""
				c.Share = ""
				c.Principal = ""
				c.Keytab = "/nonexistent/krb5-keytab"

				return c
			},
			contains: []string{
				EnvServer + " is unset",
				EnvShare + " is unset",
				EnvPrincipal + " is unset",
				"is unreadable",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.mutate(valid).Validate()

			if tc.wantOK {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}

				return
			}

			if err == nil {
				t.Fatal("Validate() = nil, want a configuration error")
			}

			if !errors.Is(err, ErrConfig) {
				t.Errorf("error %v does not wrap ErrConfig", err)
			}

			for _, want := range tc.contains {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

func TestDerivedNames(t *testing.T) {
	cfg := Config{
		Server:    "print01.corp.example.com",
		Share:     "Reception",
		Principal: "svc-probe@CORP.EXAMPLE.COM",
	}

	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "spn", got: cfg.SPN(), want: "cifs/print01.corp.example.com"},
		{name: "address", got: cfg.Address(), want: "print01.corp.example.com:445"},
		{name: "unc", got: cfg.UNC(), want: `\\print01.corp.example.com\Reception`},
		{name: "user", got: cfg.User(), want: "svc-probe"},
		{name: "realm", got: cfg.PrincipalRealm(), want: "CORP.EXAMPLE.COM"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("got %q, want %q", tc.got, tc.want)
			}
		})
	}

	t.Run("principal without a realm", func(t *testing.T) {
		bare := Config{Principal: "svc-probe"}

		if got := bare.User(); got != "svc-probe" {
			t.Errorf("User() = %q", got)
		}

		// An empty realm here is not an error: it means "fall back to
		// default_realm from krb5.conf".
		if got := bare.PrincipalRealm(); got != "" {
			t.Errorf("PrincipalRealm() = %q, want empty", got)
		}
	})
}

func TestPayload(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  string
	}{
		{name: "empty", lines: nil, want: ""},
		{
			name:  "single line",
			lines: []string{"2026-09-07T10:00:00Z  test.pyck.cloud:443  dns(ip4)  ok  0s  1 addrs"},
			want:  "2026-09-07T10:00:00Z  test.pyck.cloud:443  dns(ip4)  ok  0s  1 addrs\r\n",
		},
		{
			// The spooler is a Windows text print processor: CRLF is the only
			// transformation applied to the diagnostic output.
			name:  "lines are joined with CRLF and terminated",
			lines: []string{"first", "second", "third"},
			want:  "first\r\nsecond\r\nthird\r\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(Payload(tc.lines)); got != tc.want {
				t.Errorf("Payload() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPayloadPreservesContentVerbatim(t *testing.T) {
	// The job must carry the cycle's own output, not a rewritten version of it.
	lines := []string{
		`2026-09-07T10:00:00Z  wf.test.pyck.cloud:443    chain        ok      30ms  leaf -> YR1 -> ISRG Root X1 verified  scts=2`,
		`2026-09-07T10:00:00Z  wf.test.pyck.cloud:443    health       ok      25ms  SERVING`,
	}

	got := string(Payload(lines))
	for _, line := range lines {
		if !strings.Contains(got, line) {
			t.Errorf("payload dropped or altered %q", line)
		}
	}
}

func TestRunStopsAtTheFirstFailedStage(t *testing.T) {
	// An unreadable keytab fails P1, and no later stage may run: each stage
	// consumes the artifact the previous one produced.
	cfg := Config{
		Server:    "print01.corp.example.com",
		Share:     "Reception",
		Principal: "svc-probe@CORP.EXAMPLE.COM",
		Keytab:    filepath.Join(t.TempDir(), "absent"),
		Krb5Conf:  filepath.Join(t.TempDir(), "absent.conf"),
	}

	results := Run(t.Context(), cfg, []string{"line"})

	if len(results) != 1 {
		t.Fatalf("got %d results, want exactly the failed krb5 stage: %+v", len(results), results)
	}

	if results[0].Stage != "krb5" || results[0].OK {
		t.Errorf("first result = %+v, want a failed krb5 stage", results[0])
	}

	if results[0].Target != cfg.Address() {
		t.Errorf("target = %q, want %q", results[0].Target, cfg.Address())
	}
}
