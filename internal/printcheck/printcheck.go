// Package printcheck submits one real print job to a Windows print server over
// a Kerberos-authenticated SMB session.
//
// This is not a connectivity probe that stops at "the port answered": when it
// runs, paper comes out of a printer. It runs once, after the first cycle, and
// never again.
//
// The print server has no Internet Printing role, so there is no IPP path.
// Windows clients submit jobs with MS-RPRN over the \pipe\spoolss named pipe,
// and MS-RPRN carries no authentication of its own (MS-RPRN §2.1) — the SMB
// session is the authentication. That is why the ladder below ends in a real
// job: the same session that proves the credential is the one the job rides on.
package printcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cloudsoda/go-smb2"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"

	"github.com/pyck-ai/pyck-debug-worker/internal/report"
)

// Environment variables that configure the print check.
const (
	EnvServer    = "PYCK_PRINT_SERVER"
	EnvShare     = "PYCK_PRINT_SHARE"
	EnvPrincipal = "PYCK_KRB5_PRINCIPAL"
	EnvKeytab    = "PYCK_KRB5_KEYTAB"
	EnvKrb5Conf  = "KRB5_CONFIG"
	// envCredentialsDirectory is set by systemd for units using
	// LoadCredentialEncrypted=.
	envCredentialsDirectory = "CREDENTIALS_DIRECTORY"
)

// Defaults.
const (
	// defaultKrb5Conf matches the system-wide Kerberos configuration.
	defaultKrb5Conf = "/etc/krb5.conf"
	// credentialName is the systemd credential the keytab arrives as.
	credentialName = "krb5-keytab"
	// smbPort is the only port MS-RPRN's named pipe is reachable on.
	smbPort = "445"
	// serviceClass is the SPN class for the SMB service.
	serviceClass = "cifs"
)

// dialTimeout bounds the TCP connect to the print server.
const dialTimeout = 10 * time.Second

// ErrConfig is a startup configuration fault. --print is an imperative: if
// anything it needs is missing the binary refuses to start, rather than
// skipping the way the ambient credential-gated stages do.
var ErrConfig = errors.New("print check")

// Config is the validated print-check configuration.
type Config struct {
	// Server is the print server FQDN. Kerberos cannot map an IP address or a
	// short name onto an SPN, so nothing else is accepted.
	Server string
	// Share is the printer share name.
	Share string
	// Principal is the Kerberos principal the keytab holds a key for.
	Principal string
	// Keytab is the path to the keytab file. Its bytes are never logged.
	Keytab string
	// Krb5Conf is the path to krb5.conf.
	Krb5Conf string
}

// Load reads the configuration from the environment. getenv is injected so the
// resolution order is testable without mutating the process environment.
func Load(getenv func(string) string) Config {
	cfg := Config{
		Server:    strings.TrimSpace(getenv(EnvServer)),
		Share:     strings.TrimSpace(getenv(EnvShare)),
		Principal: strings.TrimSpace(getenv(EnvPrincipal)),
		Keytab:    strings.TrimSpace(getenv(EnvKeytab)),
		Krb5Conf:  strings.TrimSpace(getenv(EnvKrb5Conf)),
	}

	if cfg.Keytab == "" {
		if dir := strings.TrimSpace(getenv(envCredentialsDirectory)); dir != "" {
			cfg.Keytab = filepath.Join(dir, credentialName)
		}
	}

	if cfg.Krb5Conf == "" {
		cfg.Krb5Conf = defaultKrb5Conf
	}

	return cfg
}

// Validate reports every configuration fault at once, so one failed start
// tells the operator everything that is wrong rather than one item per
// attempt. It is called at the same door as the task-queue guard, before the
// loop begins.
func (c Config) Validate() error {
	var faults []string

	switch {
	case c.Server == "":
		faults = append(faults, EnvServer+" is unset")
	case net.ParseIP(c.Server) != nil:
		faults = append(faults, EnvServer+"="+c.Server+
			" is an IP address: Kerberos resolves an SPN from a name, not an address")
	case !strings.Contains(c.Server, "."):
		faults = append(faults, EnvServer+"="+c.Server+
			" is a short name: the SPN needs the fully qualified domain name")
	}

	if c.Share == "" {
		faults = append(faults, EnvShare+" is unset")
	}

	faults = append(faults, c.principalFault()...)
	faults = append(faults, c.keytabFault()...)

	if len(faults) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %s", ErrConfig, strings.Join(faults, "; "))
}

// principalFault validates the principal shape.
func (c Config) principalFault() []string {
	if c.Principal == "" {
		return []string{EnvPrincipal + " is unset"}
	}

	user, realm, hasRealm := strings.Cut(c.Principal, "@")

	switch {
	case user == "":
		return []string{EnvPrincipal + "=" + c.Principal + " has no user part"}
	case hasRealm && realm == "":
		return []string{EnvPrincipal + "=" + c.Principal + " has an empty realm after @"}
	case strings.Contains(realm, "@"):
		return []string{EnvPrincipal + "=" + c.Principal + " has more than one @"}
	default:
		return nil
	}
}

// keytabFault checks that the keytab is actually readable. Its contents are
// never read here and never logged anywhere.
func (c Config) keytabFault() []string {
	if c.Keytab == "" {
		return []string{EnvKeytab + " is unset and " + envCredentialsDirectory + " is not set either"}
	}

	file, err := os.Open(c.Keytab)
	if err != nil {
		return []string{"keytab " + c.Keytab + " is unreadable: " + err.Error()}
	}

	_ = file.Close()

	return nil
}

// User returns the principal's user part.
func (c Config) User() string {
	user, _, _ := strings.Cut(c.Principal, "@")

	return user
}

// PrincipalRealm returns the realm named in the principal, if any.
func (c Config) PrincipalRealm() string {
	_, realm, _ := strings.Cut(c.Principal, "@")

	return realm
}

// SPN is the service principal name of the print server's SMB service.
func (c Config) SPN() string {
	return serviceClass + "/" + c.Server
}

// Address is the print server's SMB endpoint.
func (c Config) Address() string {
	return net.JoinHostPort(c.Server, smbPort)
}

// UNC is the printer's UNC path, which is what RpcOpenPrinter is given.
func (c Config) UNC() string {
	return `\\` + c.Server + `\` + c.Share
}

// Run executes the print ladder once and returns one Result per stage that
// ran. lines are the rendered result lines of the first cycle — the exact text
// already written to stdout — and they are what gets printed.
//
// The stages are strictly sequential: each one consumes the artifact the
// previous one produced, so a failure is attributable to a layer instead of
// being guessed at from one opaque error.
func Run(ctx context.Context, cfg Config, lines []string) []report.Result {
	var results []report.Result

	// P1 krb5: the keytab is valid, the realm is right, a KDC answered, and
	// the clock is inside the allowed skew.
	krbClient, result := loginStage(cfg)
	results = append(results, result)

	if !result.OK {
		return results
	}

	defer krbClient.Destroy()

	// P2 spn: the print server's SPN exists in the directory.
	results = append(results, ticketStage(cfg, krbClient))
	if !last(results).OK {
		return results
	}

	// P3 smb: the print server accepted our ticket.
	session, result := sessionStage(ctx, cfg, krbClient)
	results = append(results, result)

	if !result.OK {
		return results
	}

	defer func() { _ = session.Logoff() }()

	// P4 share: the printer is shared under that name.
	results = append(results, shareStage(session, cfg))
	if !last(results).OK {
		return results
	}

	// P5 submit: a real job reaches the spooler.
	return append(results, submitStage(ctx, cfg, lines))
}

// loginStage performs P1.
func loginStage(cfg Config) (*client.Client, report.Result) {
	var krbClient *client.Client

	result := stage(cfg, "krb5", func() (bool, string) {
		table, err := keytab.Load(cfg.Keytab)
		if err != nil {
			return false, "keytab " + cfg.Keytab + ": " + classify(err)
		}

		settings, err := config.Load(cfg.Krb5Conf)
		if err != nil {
			return false, cfg.Krb5Conf + ": " + classify(err)
		}

		realm := cfg.PrincipalRealm()
		if realm == "" {
			realm = settings.LibDefaults.DefaultRealm
		}

		if realm == "" {
			return false, "no realm: " + EnvPrincipal +
				" carries no @REALM and " + cfg.Krb5Conf + " sets no default_realm"
		}

		// DisablePAFXFAST is required against Active Directory, which does not
		// respond to FAST the way the RFC expects.
		candidate := client.NewWithKeytab(cfg.User(), realm, table, settings,
			client.DisablePAFXFAST(true))

		if err := candidate.Login(); err != nil {
			return false, classify(err)
		}

		krbClient = candidate

		return true, cfg.User() + "@" + realm + " logged in, " +
			fmt.Sprintf("%d keytab entries", len(table.Entries))
	})

	return krbClient, result
}

// ticketStage performs P2.
func ticketStage(cfg Config, krbClient *client.Client) report.Result {
	return stage(cfg, "spn", func() (bool, string) {
		ticket, _, err := krbClient.GetServiceTicket(cfg.SPN())
		if err != nil {
			return false, cfg.SPN() + ": " + classify(err)
		}

		// Only the etype and the ticket's own naming are readable here: the
		// encrypted part is sealed with the service's key, so a client-side
		// expiry would be a zero value dressed up as a timestamp.
		return true, fmt.Sprintf("%s ticket for %s@%s etype=%d",
			cfg.SPN(),
			strings.Join(ticket.SName.NameString, "/"),
			ticket.Realm,
			ticket.EncPart.EType)
	})
}

// sessionStage performs P3.
func sessionStage(ctx context.Context, cfg Config, krbClient *client.Client) (*smb2.Session, report.Result) {
	var session *smb2.Session

	result := stage(cfg, "smb", func() (bool, string) {
		dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		defer cancel()

		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", cfg.Address())
		if err != nil {
			return false, cfg.Address() + ": " + classify(err)
		}

		dialer := &smb2.Dialer{
			Initiator: &smb2.Krb5Initiator{Client: krbClient, TargetSPN: cfg.SPN()},
		}

		established, err := dialer.DialConn(dialCtx, conn, cfg.Address())
		if err != nil {
			_ = conn.Close()

			return false, classify(err)
		}

		session = established

		return true, cfg.Address() + " session established as " + cfg.Principal
	})

	return session, result
}

// shareStage performs P4.
func shareStage(session *smb2.Session, cfg Config) report.Result {
	return stage(cfg, "share", func() (bool, string) {
		names, err := session.ListSharenames()
		if err != nil {
			return false, classify(err)
		}

		if !slices.Contains(names, cfg.Share) {
			return false, fmt.Sprintf("%q absent from %d shares on %s",
				cfg.Share, len(names), cfg.Server)
		}

		return true, fmt.Sprintf("%q present (%d shares)", cfg.Share, len(names))
	})
}

// stage times fn and turns it into a Result, in the same shape as every other
// line this binary prints.
func stage(cfg Config, name string, fn func() (bool, string)) report.Result {
	started := time.Now()
	ok, detail := fn()

	return report.Result{
		Ts:       started.UTC(),
		Target:   cfg.Address(),
		Stage:    name,
		OK:       ok,
		Duration: time.Since(started),
		Detail:   detail,
	}
}

// last returns the most recent result.
func last(results []report.Result) report.Result {
	return results[len(results)-1]
}
