# pyck-debug-worker — implementation plan

Standalone diagnostic binary that probes pyck endpoints every 30s across
DNS → TCP → TLS → HTTP/2 → gRPC → Temporal, including the worker long-poll path.

Single static binary (win/mac/linux × amd64/arm64) + `ghcr.io/pyck-ai/baseimages/static` container.

## Goal / non-goals

**Goal:** prove — or precisely disprove — reachability of pyck endpoints, and
resolve the tenant id when credentials are present.

**Non-goals:** no metrics endpoint, no alerting, no config server, no workflow
execution, no writes of any kind, no security-posture grading.

## Output contract

Plain stdlib log lines, no color, no TTY detection, no redraw, UTC RFC3339.

```
<ts>  <target>  <stage>  <status>  <duration>  <detail>
```

* Status set is exactly **`ok`** and **`FAIL`**. There is no WARN, no INFO, no SKIP.
* A stage whose gate is not satisfied prints **nothing at all**.
* Absent credentials are never mentioned — not in the config banner, not per cycle.
* Secrets are never printed in any form.

### Cycle summary

Every cycle ends with a summary block: one line per target carrying that target's
rolled-up status, then a single `OVERALL`. A target is `OK` only if every stage
that ran for it returned `ok`.

Column widths are **computed, never hand-aligned**: label field is `max(label)+2`,
status right-aligned in 4, counts right-aligned in `max(counts)+3`, extras after
3 spaces. All rules are 64 chars. `uptime` is `cycle.At - runStart`, so cycle 1
shows ~`0s` because the first cycle runs immediately rather than after one interval.

```
---- cycle 1  2026-09-04T09:41:01Z  1.31s ----------------------
  wf.test.pyck.cloud:443    OK   11/11
  test.pyck.cloud:443       OK     6/6
  OVERALL                   OK   17/17   uptime 30s
----------------------------------------------------------------
```

On failure the same block names the failing stages, so the summary is sufficient
without scrolling back:

```
---- cycle 6  2026-09-04T09:43:37Z  5.21s ----------------------
  wf.test.pyck.cloud:443  FAIL    9/11   tcp(ip6) temporal
  test.pyck.cloud:443       OK     6/6
  OVERALL                 FAIL   15/17   uptime 2m45s  failing 1m15s
----------------------------------------------------------------
```

`failing` is the elapsed time since the first cycle that was not fully `OK`, and
is omitted while healthy.

### Run summary

On SIGINT/SIGTERM a final block reports the whole run, then the process exits.

```
---- run summary  ----------------------------------------------
  cycles 3   clean 2   degraded 1
  wf.test.pyck.cloud:443    OK   32/33   last fail 09:41:31
  test.pyck.cloud:443       OK   18/18
  OVERALL                 FAIL   50/51   uptime 1m30s
----------------------------------------------------------------
```

`OVERALL` in the run summary is `FAIL` if **any** cycle failed, even if the final
cycle was clean — a prober that hides a transient outage is useless.

Exit code: `0` if every cycle was clean, `1` if any cycle contained a failure,
`2` for a config/usage error (including a rejected secret-bearing flag).

## Target resolution

Hostnames follow `<svc>${SEP}${DOMAIN}` (deployment/application/kustomize/scripts/render.sh:168-172).

| `--env`        | DOMAIN                 | SEP | Temporal frontend             | app / gateway            |
|----------------|------------------------|-----|-------------------------------|--------------------------|
| `local`        | `local-test.pyck.cloud`| `.` | `wf.local-test.pyck.cloud`    | `local-test.pyck.cloud`  |
| `dev`          | `dev.pyck.cloud`       | `.` | `wf.dev.pyck.cloud`           | `dev.pyck.cloud`         |
| `test`         | `test.pyck.cloud`      | `.` | `wf.test.pyck.cloud`          | `test.pyck.cloud`        |
| `demo`         | `demo.pyck.cloud`      | `.` | `wf.demo.pyck.cloud`          | `demo.pyck.cloud`        |
| `prod`         | **`eu.pyck.cloud`**    | `.` | `wf.eu.pyck.cloud`            | `eu.pyck.cloud`          |
| `feature/<b>`  | `feature.pyck.cloud`   | **`-`** | `wf-<b>.feature.pyck.cloud` | `<b>.feature.pyck.cloud` |

Two traps: prod's domain is `eu`, not `prod`; feature envs use `-` as separator.

Default target set per env is the Temporal frontend plus the app domain.
Anything else must be named explicitly with `--target host:port[=grpc|https]`.

In-cluster mode: `--target pyck-temporal-internal-frontend:7236=grpc --insecure`
(plaintext, no credentials, namespace `default`).

### Never probed

Hardcoded denylist; a 30s prober against these causes real damage.

| endpoint                  | reason                                  |
|---------------------------|-----------------------------------------|
| `otel.` / `otel-grpc.`    | OTLP write path                         |
| `<env>.pyck.cloud/ws`     | NATS websocket — leaks server-side conns|
| `storage.` / `remote-ui-*`| billable Hetzner S3 egress              |
| `boxes-nonprod.`          | may spawn sandboxes                     |
| worker-api log-follow     | long-lived stream                       |

The denylist is host/path-matched. Polling a **real Temporal task queue** is the
one remaining hazard it cannot express — it is enforced separately by the
task-queue config check in M3, which pins the queue to `pyck-debug-worker-probe`.

`--target host:port[=grpc|https]` defaults to `https` when the kind is omitted.

Preferred probe targets, confirmed unauthenticated and 200-able:
`<env>.pyck.cloud/static/settings.json`,
`auth.<env>.pyck.cloud/.well-known/openid-configuration`,
`worker-api*/healthz`.

Rate limits are 300/s per IP and 50/s per tenant on `/graphql`; at 1 req/30s we are
~4 orders of magnitude under, and Traefik's limiter keeps no ban state.

## Probe ladder

Explicit pipeline — each stage consumes the previous stage's artifact so a failure
is attributable. Never `http.Get` and reverse-engineer which layer broke.

| # | stage       | api                                                        | gate                 |
|---|-------------|------------------------------------------------------------|----------------------|
| 1 | `dns`       | `net.Resolver{PreferGo:true}.LookupNetIP`, ip4/ip6 separate | always               |
| 2 | `tcp`       | `net.Dialer.DialContext` **per resolved IP**                | always               |
| 3 | `tls`       | `tls.Client` + `HandshakeContext`                           | always               |
| 4 | `cert`      | leaf: CN, SAN count, key algo/bits, expiry                  | always               |
| 5 | `chain`     | manual `leaf.Verify()`, root anchor, SCT count              | always               |
| 6 | `http2`     | `http2.Transport` (no h1 fallback)                          | https targets        |
| 7 | `redirect`  | `:80` with `CheckRedirect` disabled                         | https targets        |
| 8 | `grpc`      | `grpc.NewClient` + `Connect()` + `WaitForStateChange`       | grpc targets         |
| 9 | `health`    | `grpc_health_v1.Health/Check`                               | grpc targets         |
|10 | `temporal`  | `WorkflowService().GetSystemInfo`                           | key **or** `--insecure` |
|11 | `namespace` | `DescribeNamespace`                                         | key **or** `--insecure` |
|12 | `longpoll`  | `worker.Start()` + `DescribeTaskQueue`                      | `--deep` + key       |
|13 | `auth`      | `GetMe` GraphQL                                             | pyck service token   |
|14 | `tenant`    | see below                                                   | pyck service token   |

Stage 5 verifies manually (`InsecureSkipVerify` then `leaf.Verify()`) so all faults
are reported rather than only the first. `x509.Expired` conflates expired and
not-yet-valid — disambiguate against `NotBefore`/`NotAfter` explicitly.

OCSP is **not checked**: Let's Encrypt removed OCSP URLs from certs 2025-05-07 and
switched off responders 2025-08-06. Every pyck cert is LE, so there is never a staple.

### Settled implementation decisions

* **One handshake, not two.** `tls` handshakes with `InsecureSkipVerify: true`;
  `cert` and `chain` then verify the resulting `ConnectionState` manually. A
  verifying handshake aborts on the first fault, which would suppress the `cert`
  and `chain` results entirely. Consequence: `tls` reports `ok` on a bad
  certificate — the verdict lives in the stage named after it.
* **Never assert the issuer CN.** Observed 2026-09-04: `wf.test.pyck.cloud` chains
  `leaf -> Let's Encrypt YR1 -> ISRG Root YR -> ISRG Root X1`. Let's Encrypt has
  rotated off the R10/R11 intermediates, so any hardcoded issuer assertion would
  now fail on every healthy pyck endpoint. Report the chain; do not judge it.
* **A missing AAAA is `ok`.** Every pyck host is A-only today. With no WARN status,
  treating an absent IPv6 record as FAIL would paint healthy hosts red. `dns` FAILs
  only when neither family resolves or the lookup genuinely errors.
* **`--insecure` skips `tls`/`cert`/`chain`** — it selects the plaintext in-cluster
  path (`:7236`), where a handshake fails by construction.
* Stage names use the `LookupNetIP` network spelling: `dns(ip4)`, `tcp(ip6)`.

### Correctness rules

* `grpc.NewClient` performs **no I/O**. A nil error means the config parsed. Never
  render it as connected.
* `codes.Unimplemented` from health or reflection is a **success** signal for
  reachability — a well-formed gRPC status returned over h2.
* Use `WorkflowService()` directly; it bypasses SDK auto-retries so RTTs are clean.
* A mid-poll `GOAWAY` is expected (Traefik HPA 3–6, 15s preStop) and is not a failure.

### Error taxonomy

| signal | verdict |
|---|---|
| ctx deadline before any status | firewall drop |
| `Unavailable` + resolver message | DNS |
| `x509.UnknownAuthorityError` | CA bundle |
| `Unauthenticated` | bad API key |
| `PermissionDenied` | not authorised for this namespace — see note |
| `NotFound` on DescribeNamespace | namespace typo, **not** an auth fault |
| `ResourceExhausted` | rate-limited but reachable |
| health OK + `GetSystemInfo` `Unauthenticated`/`PermissionDenied` | definitively auth, not network |

**Verified against live pyck 2026-09-04:** the frontend returns `PermissionDenied`
for an outright garbage API key, not only for a valid-identity-wrong-scope case.
Never word this verdict as "valid identity" — it would tell an operator their
credential is fine when it is junk. `Unauthenticated` may never appear at pyck,
so the health-OK rule must cover both codes.

`serviceerror` types implement `Status()`, not `GRPCStatus()`, so `status.Code`
and `status.FromError` are **blind to them** and the whole taxonomy silently
bypasses. Classification must check both interfaces.

Reuse the code→sentinel mapping in `worker-api/internal/temporalcheck/validate.go:96-109`.

## Tenant resolution

Two token shapes; only one is offline-decodable.

| token | env var | shape | resolution |
|---|---|---|---|
| service / worker | `PYCK_API_TOKEN`, `PYCK_SERVICE_TOKEN` | opaque Zitadel PAT | **network call required** |
| CLI user | `PYCK_AUTH` | JWT | offline `pyck_tenant_id` claim |

1. Shape-detect (`IsValidJWT` — stdlib split + base64, no jwt dependency).
2. JWT → decode top-level `pyck_tenant_id` → `via=jwt-claim`.
   Fallback `ComputeUUID(iss, resourceowner_id)` → `via=computed`, where
   `ComputeUUID(ns, s) = uuid.NewSHA1(uuid.NewSHA1(uuid.NameSpaceOID, ns), s)`
   (two-stage UUIDv5, `pyck/backend/common/authn/uuid.go:14-17`).
   Issuer is `https://auth.<env>.pyck.cloud`; audience == issuer.
3. PAT → `POST https://<env>.pyck.cloud/graphql` with the read-only `GetMe` query,
   read `data.me.TenantID` / `TenantName` → `via=api`. This doubles as the auth
   check, so stages 13+14 are one call for PATs.
4. `PYCK_API_TENANT_ID` is an **input**, never derived. Diff it and
   `TEMPORAL_NAMESPACE` against the resolved value; a mismatch is `FAIL` and is the
   highest-value signal in the tool.

For PATs the tenant stage depends on the gateway, so it chains after the app domain.
The binary never mints tokens — no `client_credentials` grant exists at pyck.

## Secrets

`/proc/<pid>/cmdline` is mode `0444` by default on every mainstream distro and
container image, so argv is world-readable.

* Secrets come from **env vars or `--token-file` only**.
* The binary actively rejects `--token` / `--api-key` with an explanatory exit 2.
* A `Secret` struct with an unexported field implements `fmt.Formatter`, `String`,
  `GoString`, `MarshalJSON`, `MarshalText` and `slog.LogValue`, all returning
  `sha256:<8 hex>…(len=N)`. `Reveal()` is the sole accessor, making
  `grep -rn '\.Reveal()'` a complete audit.
* Never `type Secret string` — a defined string type is still convertible.
* `url.URL.Redacted()` on every URL that reaches an error or log line.

## Loop

`time.Ticker(30s)` with jitter. Each cycle gets a fresh
`context.WithTimeout(parent, 25s)` so a hung probe cannot stall the next tick.
Targets probed concurrently under a bounded `sync.WaitGroup` + semaphore (max 8).
Deliberately not `errgroup` — it would be a new dependency for no benefit.

`*grpc.ClientConn` and the Temporal client are **reused** across cycles — their
reconnect behaviour is itself signal. DNS/TCP/TLS are rebuilt every cycle.

`longpoll` is a persistent worker started once at boot on the dedicated queue
`pyck-debug-worker-probe`, reporting observed state per cycle. It never polls a
real queue, so no live work is stolen. It is the only test of Traefik's
`readTimeout 60s` default, which is unset in the deployment repo and is the value
most likely to truncate a Temporal long poll.

Clean SIGINT/SIGTERM shutdown with `worker.Stop()` drained.

## Config

Temporal env contract (SDK `contrib/envconfig`): `TEMPORAL_ADDRESS`,
`TEMPORAL_NAMESPACE` (= tenant UUID), `TEMPORAL_API_KEY`, `TEMPORAL_TLS`.
pyck: `PYCK_API_TOKEN` / `PYCK_SERVICE_TOKEN` / `PYCK_AUTH`, `PYCK_API_TENANT_ID`,
`PYCK_GATEWAY_URL`.

API-key credentials auto-enable TLS in the SDK; local plaintext needs explicit
`TLSDisabled: true`.

Flags: `--env` (repeatable) · `--target` (repeatable) · `--interval 30s` ·
`--namespace` · `--insecure` · `--deep` · `--task-queue` · `--ca-bundle` ·
`--token-file` · `--debug-dns` (sets `GODEBUG=netdns=go+1` and captures the
resolver's own decision trace).

## Repo layout

Copies `cli/` house conventions. Module `github.com/pyck-ai/pyck-debug-worker`.

```
cmd/pyck-debug-worker/main.go
internal/target/    env → hostname resolution, denylist
internal/probe/     dns tcp tls cert chain http2 redirect grpc temporal worker
internal/secret/    Secret type
internal/report/    Result model + line renderer
internal/buildinfo/
Taskfile.yml        build install test vet lint check tidy release:snapshot tag default
.golangci.toml      v2, gofumpt + gci prefix(github.com/pyck-ai/)
.goreleaser.yml
Dockerfile
.github/workflows/  ci.yml release.yml build.yml
```

Deviations from house convention, deliberate: stdlib `flag` instead of urfave/cli
v3, and stdlib logging instead of zerolog — both to keep the binary small and the
output plain. Build stamping is **commit only**, no build date, because a
timestamp destroys bit-for-bit reproducibility; `-buildvcs` supplies the rest.

## Container

```dockerfile
FROM ghcr.io/pyck-ai/baseimages/static:latest
COPY --from=build /out/pyck-debug-worker /pyck-debug-worker
ENTRYPOINT ["/pyck-debug-worker"]
```

Builder is `ghcr.io/pyck-ai/baseimages/golang:1.26-alpine` with BuildKit mod and
build caches. `CGO_ENABLED=0 -trimpath -tags netgo,osusergo -ldflags="-s -w -X …buildCommit"`.

Runtime is `ghcr.io/pyck-ai/baseimages/static:latest`, the house scratch-derived
image for statically-compiled binaries. It already ships the CA bundle
(`/etc/ssl/certs/ca-certificates.crt` + `SSL_CERT_FILE`), a minimal
`/etc/passwd`/`/etc/group` (root + `nonroot`), UTC `/etc/localtime` +
`/usr/share/zoneinfo`, and defaults to `USER 1001` (numeric — scratch has no
`/etc/passwd` for a name to resolve against) — so the Dockerfile no longer needs
to stage the certs bundle itself or set `USER` explicitly. It ships no
`/etc/nsswitch.conf`; Go's pure-Go resolver falls back to `files dns` order in
its absence, matching what the tool wants.

Gotchas: scratch (via `static`) has none of the six CA paths `crypto/x509`
probes, but the bundle is provisioned by the base image. `/etc/resolv.conf` is
runtime-mounted by Docker/K8s — the `dns` stage reports the resolver config it
used so an odd network mode is visible. `netgo,osusergo` are redundant under
`CGO_ENABLED=0` but are fail-loud insurance. `time/tzdata` is **not** imported;
all timestamps are UTC.

Using `baseimages/static` instead of a hand-rolled `FROM scratch` keeps the
diagnostic surface (certs, passwd, timezone, nonroot uid) on the same audited,
Renovate-tracked base every other pyck.ai image uses, rather than a bespoke copy
of the same files maintained only here.

## Release

goreleaser v2, `linux/darwin/windows × amd64/arm64`, tar.gz plus zip on Windows,
`checksums.txt`, published to GitHub Releases on tag `v*`. Image pushed to
`ghcr.io/pyck-ai/pyck-debug-worker`. CI runs vet/test/lint/build plus `govulncheck`.

Supply chain, ~20 lines of YAML and 0 binary bytes: goreleaser native `sboms:`
(requires `anchore/sbom-action/download-syft` on the runner — syft is not
preinstalled) plus `actions/attest@v4` with `subject-checksums: ./dist/checksums.txt`
— one step attests all six artifacts, SLSA Build L3 on GitHub-hosted runners.
Cosign keyless signing is rejected: it duplicates the GitHub attestation and
publishes repo identity to the public Rekor log.

**Verified 2026-09-05:** build provenance attestation is **not available for
private repos on the pyck-ai plan** (`Failed to persist attestation: Feature not
available for the pyck-ai organization`). The step is gated on
`!github.event.repository.private` so releases stay green; it starts working by
itself if the repo is made public or the plan is upgraded. SBOMs are unaffected.

Releases are **immutable** in this org: a published release cannot receive
assets afterwards. `v1.0.0` was published empty and can never be populated —
retag rather than retry. Workflow `permissions:` blocks are all-or-nothing; a
block that omits `contents: read` breaks `actions/checkout` on a private repo
with a misleading `Repository not found`.

macOS caveat to print as a startup banner on darwin: `CGO_ENABLED=0` forces the
pure-Go resolver, so split-horizon DNS, VPN resolvers and `.local`/mDNS will not
resolve.

## Size budget

Measured, `CGO_ENABLED=0 -trimpath -ldflags="-s -w"`, linux/amd64:

| variant | contents | size |
|---|---|---|
| a | stdlib + `x/net/http2` | 5.9 MB |
| b | + grpc-go + `go.temporal.io/api` | 16.0 MB |
| c | + Temporal SDK + worker | 20.6 MB |
| d | c + full x509 report + OCSP + uuid + json + stdlib flag | 20.6 MB |

The entire security-reporting layer costs **+0.04 MB** — `crypto/x509` is already
linked by TLS and gRPC. Size and depth are not in conflict.

Rejected on cost: CT signature *verification* (+3.63 MB), embedded HSTS preload
list (+10.5 MB), UPX (~7 MB achievable, but Windows AV false-positives on a
diagnostic tool is a bad trade).

## Print check (Kerberos, RHEL 9) — real job, printed once at startup

Original ask: a flag that, on start only (never on the 30s loop), prints the
first cycle's diagnostic output onto paper on a real Windows print server. This
submits an actual job — not a connectivity-only proof.

**Constraints that shape it:** RHEL 9 only. The print server has **no Internet
Printing role**, so there is no IPP/HTTP path. Windows print clients submit jobs
via **MS-RPRN** (`RpcOpenPrinter` → `RpcStartDocPrinter` → `RpcStartPagePrinter`
→ `RpcWritePrinter` → `RpcEndPagePrinter` → `RpcEndDocPrinter` →
`RpcClosePrinter`) over an SMB named pipe (`\pipe\spoolss`). MS-RPRN itself
carries no authentication — *the SMB session is the authentication* (MS-RPRN
§2.1) — so a Kerberos-authenticated SMB session is both the auth proof and the
transport the real job rides on.

### Flag and content

`--print` (bool). Fires **once**, after cycle 1 completes and before the ticker
starts — never inside the loop. Content is the **exact rendered lines of cycle
1** (`report.Cycle`, the same text already written to stdout), submitted as a
`text` datatype job so the print server renders it as plain text.

Unlike the ambient credential-gated stages, `--print` is an explicit imperative:
if it is set and any of its prerequisites are missing, that is a **startup
config error, not a silent skip** — exit 2 with the specific missing piece,
checked at the same door as the task-queue guard.

### Stages

`krb5` → `spn` → `smb` → `share` (unchanged from the connectivity design, table
below) → **`submit`**, the real MS-RPRN sequence. Only `submit` is new.

| # | stage | api | proves |
|---|---|---|---|
| P1 | `krb5` | `keytab.Load` → `client.NewWithKeytab(…, DisablePAFXFAST(true))` → `Login()` | keytab valid, realm right, KDC reachable, clock within skew |
| P2 | `spn` | `GetServiceTicket("cifs/<fqdn>")` | the print server's SPN is registered in AD |
| P3 | `smb` | `go-smb2` `Dial` with `Krb5Initiator{TargetSPN: "cifs/<fqdn>"}` to `:445` | the print server **accepted our ticket** |
| P4 | `share` | `ListSharenames` contains `PYCK_PRINT_SHARE` | the printer is shared under that name |
| P5 | `submit` | MS-RPRN `RpcOpenPrinter` … `RpcClosePrinter` over the authenticated session, `datatype=text` | **a real job reached the spooler and printed** |

Env: `PYCK_PRINT_SERVER` (**FQDN** — Kerberos cannot map an IP or short name to
an SPN), `PYCK_PRINT_SHARE` (required when `--print` is set), `PYCK_KRB5_PRINCIPAL`,
`PYCK_KRB5_KEYTAB` (default `$CREDENTIALS_DIRECTORY/krb5-keytab`), `KRB5_CONFIG`
(default `/etc/krb5.conf`). Realm from the principal's `@REALM` suffix, else
`default_realm`.

### Auth implementation

`go-msrpc` is the Go implementation of MS-RPRN and takes a keytab natively
(`ssp/credential/keytab.go`, with a direct converter from a `gokrb5/v8`
keytab), so `submit` uses its client end to end — the same keytab as P1–P3,
no separate credential flow. Only `ssp.SPNEGO` and `ssp.KRB5` are registered;
there is no NTLM mechanism anywhere in the process.

### Kerberos-or-fail

`gokrb5` offers **only** the Kerberos mech in its SPNEGO token, so an NTLM
fallback is impossible from our side by construction. Refuse RC4 in
`krb5.conf`: `permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96`,
`allow_weak_crypto = false`. Server 2025 DCs no longer issue RC4 TGTs anyway;
the account must have AES keys (`msDS-SupportedEncryptionTypes = 24`).

### Credential — the RHEL 9 path, and only that path

**One recommended source:** join the box to AD and create a Managed Service
Account with `adcli create-msa`. SSSD rotates its password every 30 days; no human
ever knows it. Fallback if IT will not join the box: a keytab exported for a
dedicated service account.

**One storage mechanism:** systemd encrypted credentials (systemd 252 on RHEL 9;
`LoadCredentialEncrypted=` since 250). Sealed to the TPM2 and/or host key, only
decrypted into non-swappable memory while the unit runs, visible to the unit's
UID only. Works with the existing `DynamicUser=yes`.

```sh
systemd-creds encrypt --name=krb5-keytab svc.keytab /etc/credstore.encrypted/krb5-keytab
shred -u svc.keytab
```
Use `--with-key=host` on VMs without a vTPM; `auto` fails there.

Delivered as a **drop-in**, not in the base unit — `LoadCredentialEncrypted=`
has no "optional" form and would fail units that do not use the check:
`contrib/systemd/pyck-debug-worker@.service.d/kerberos.conf`.

Rotation trap to document: credentials are snapshotted at unit start, so after
SSSD rotates the MSA key the **next** `Login()` fails with `KDC_ERR_PREAUTH_FAILED`
until the unit is restarted. Restart, do not debug.

Never: password or keytab bytes in `Environment=`, argv, or the unit file. The
binary already refuses secret-bearing flags.

### Error taxonomy (string-matched — `krberror` has no `Unwrap`)

| signal | verdict |
|---|---|
| `failed to communicate with KDC` | no KDC reachable — DNS/firewall to the DC |
| `KDC_ERR_PREAUTH_FAILED` | wrong or **stale** keytab (key rotated → restart unit) |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | account missing or disabled |
| `KRB_AP_ERR_SKEW` | clock skew > 300s — check `chronyc tracking` |
| `KDC_ERR_ETYPE_NOSUPP` | account has no AES keys (RC4-only) |
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` | `cifs/<fqdn>` unknown — wrong FQDN or server not domain-joined |
| `KDC did not respond appropriately to FAST` | AD quirk — `DisablePAFXFAST(true)` missing |
| SMB session rejected after valid ticket | server-side: account not permitted, or SMB policy |
| share absent from list | printer not shared under that name |
| `RpcOpenPrinter`/spooler RPC fault | share exists but isn't a printer, or spooler service down |
| job accepted but never leaves the queue | driver/paper/offline issue on the printer itself — outside this tool |

### Verification

Samba AD DC in Docker is both the KDC and an SMB server: `samba-tool domain
provision`, a service user, a `[printers]` share. Forced failures: corrupt
keytab → `PREAUTH_FAILED`; ask for `cifs/nope.test.lan` → `S_PRINCIPAL_UNKNOWN`;
`faketime` → `SKEW`; wrong share name → `share` FAIL.

### Cost

Measured, `CGO_ENABLED=0 -trimpath -tags netgo,osusergo -ldflags="-s -w"`,
linux/amd64: **20.67 MiB before, 27.22 MiB after — +6.55 MiB** for the whole
feature (`gokrb5/v8` + `CloudSoda/go-smb2` for P1–P4, plus `go-msrpc` with its
bundled `gokrb5.fork/v9` and `go-smb2.fork` for P5).

Larger than the earlier per-library estimates because `go-msrpc` brings a second
complete Kerberos and SMB stack of its own: it authenticates from the keytab
itself rather than accepting the ticket P1–P3 already obtained. That is the cost
of **auth branch 1** below, which is the branch this needed.

`CGO_ENABLED=0` still cross-compiles cleanly for linux/darwin/windows on
amd64 and arm64 — no build-config change required.

### Extra README

`contrib/kerberos/README.md`, short: this performs a **real print** — a page
comes out of a physical printer every time `--print` is set and the worker
starts. State that plainly at the top, not buried. Then: the AD prerequisites,
the RHEL 9 credential recipe above, the drop-in, and the error table. Nothing
about RHEL 8, IPP, or alternatives.

## Milestones

| M | content | lane |
|---|---|---|
| M1 | skeleton, Taskfile, golangci, CI; `--env` resolver + denylist; dns/tcp/tls/cert/chain; line renderer | @fixer |
| M2 | http2 + redirect + grpc + health; error taxonomy | @fixer |
| M3 | temporal + namespace + longpoll; secret type; auth + tenant | @fixer |
| M4 | scratch Dockerfile, goreleaser, workflows, SBOM + attestation | @fixer |

M1→M3 are sequential on the shared `Result` model. M4 is parallel to M2/M3.

## Verification

Local `temporalio/temporal server start-dev` in Docker for the plaintext path and
to force each failure mode: kill the server → `Unavailable`; wrong key →
`Unauthenticated`; wrong namespace → `NotFound`. Then read-only against real
`test.pyck.cloud` / `wf.test.pyck.cloud`.
