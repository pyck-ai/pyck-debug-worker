# pyck-debug-worker

Probes pyck endpoints every 30s across DNS → TCP → TLS → HTTP/2 → gRPC → Temporal,
including the worker long-poll path. One static binary, no runtime deps.

Answers "is it reachable, and if not, which layer is broken" — and resolves your
tenant id.

## Install

```sh
# release binary (linux/darwin/windows × amd64/arm64)
curl -sSL https://github.com/pyck-ai/pyck-debug-worker/releases/latest/download/pyck-debug-worker_linux_amd64.tar.gz | tar xz

# container
docker run --rm ghcr.io/pyck-ai/pyck-debug-worker --env test

# from source
task build
```

## Use

```sh
pyck-debug-worker --env test
pyck-debug-worker --env prod --env dev
```

`--env` resolves both the Temporal frontend and the app domain. Note `prod` is
`eu.pyck.cloud`, and `feature/<branch>` uses a `-` separator.

That is the entire surface: `--env` and `--version`, plus `--token-file` for
credentials (see below) and the opt-in `--netcheck` measurement
([below](#long-term-network-quality---netcheck)). Everything else — interval,
task queue, deep long-poll, CA trust — is a fixed, safe default. Nothing to
misconfigure.

## Credentials are optional, and gate what runs

Stages whose credentials are absent print **nothing** — no skip lines, no noise.

| you set | you additionally get |
|---|---|
| nothing | `dns` `tcp` `tls` `cert` `chain` `http2` `redirect` `grpc` `health` |
| `TEMPORAL_API_KEY` | `temporal` `namespace` (+ `longpoll` with `--deep`) |
| `PYCK_API_TOKEN` | `auth` `tenant` |

Other env vars: `PYCK_SERVICE_TOKEN` / `PYCK_AUTH` (alternatives to
`PYCK_API_TOKEN`), `PYCK_API_TENANT_ID`, `PYCK_GATEWAY_URL`, `TEMPORAL_NAMESPACE`.

**Secrets are env-only.** `--token` and `--api-key` are refused: argv is
world-readable via `/proc/<pid>/cmdline`. Use the environment or `--token-file`.
Credentials are never printed — only a `sha256:` fingerprint.

## Output

```
2026-09-04T11:07:01Z  wf.test.pyck.cloud:443  tls       ok     32ms  TLS1.3 alpn=h2 TLS_AES_128_GCM_SHA256
2026-09-04T11:07:01Z  wf.test.pyck.cloud:443  cert      ok       0s  CN=wf.test.pyck.cloud sans=1 RSA2048 expires=2026-12-03 (89d)
2026-09-04T11:07:01Z  wf.test.pyck.cloud:443  chain     ok     30ms  leaf -> YR1 -> Root YR -> ISRG Root X1 verified  scts=2
2026-09-04T11:07:01Z  wf.test.pyck.cloud:443  health    ok     25ms  SERVING
2026-09-04T11:07:01Z  wf.test.pyck.cloud:443  temporal FAIL    125ms  permission denied — health answered, so this is definitively auth, not the network
---- cycle 1  2026-09-04T11:07:01Z  257ms ----------------------
  wf.test.pyck.cloud:443  FAIL    8/10   temporal namespace
  test.pyck.cloud:443       OK     8/8
  OVERALL                 FAIL   16/18   uptime 0s  failing 0s
----------------------------------------------------------------
```

Two statuses only: `ok` and `FAIL`. Each cycle ends with a per-target rollup and
an `OVERALL`; SIGINT/SIGTERM prints a run summary.

## Flags

| flag | |
|---|---|
| `--env` | environment to probe, repeatable |
| `--token-file` | file holding a credential (alternative to the env vars above) |
| `--print` | after the first cycle, post that cycle's lines to fax.pyck.cloud and print a QR label linking to them on a Windows print server's ZPL label printer — **a real label comes out** ([setup](contrib/kerberos/README.md)) |
| `--netcheck` | also measure long-term connection quality and write it to `./netcheck/` ([details](#long-term-network-quality---netcheck)) |
| `--netcheck-hosts` | with `--netcheck`: comma-separated hosts to measure, default `dev.pyck.cloud` |
| `--netcheck-upload` | with `--netcheck`: upload each finished day to `debug.pyck.cloud` |
| `--version` | print version and exit |

## Long-term network quality (`--netcheck`)

```sh
pyck-debug-worker --env test --netcheck --netcheck-hosts=region-sing.pyck.cloud,dev.pyck.cloud
```

Runs beside the 30s probe cycle and never changes the exit code. Every A record
of every host (resolved at startup and every 5 min) is one target, measured two
ways:

* **short** — every 10s a fresh TCP connect + TLS handshake, then close. No
  HTTP request is sent. Records connect and handshake time; failures are
  `timeout`, `refused`, `reset`, `intercepted` or `other`; a connect taking ≈1s
  or ≈3s counts as a lost SYN.
* **long** — one HTTP/2 connection, PING every 1s. Records PING RTT, unanswered
  PINGs (5s), drops with lifetime and error, and on Linux the kernel's `TCP_INFO`
  (rtt, rttvar, retransmits). A server GOAWAY (e.g. nginx `keepalive_time`) is
  `server-closed`, not a drop. No PING answered for 30s is a drop. Reconnects
  with backoff.

TLS uses the host as SNI and **verifies the certificate** for it against the
system roots. A handshake that presents a certificate failing verification is
`intercepted` (a TLS-inspecting middlebox, or a broken server certificate): the
leaf's SHA-256 fingerprint, issuer CN and the verification error are recorded,
the short connection's handshake time still counts, and the long connection is
not used for PINGs. A bare-IP entry has no name to verify: no SNI, no
verification. Hosts must not be Cloudflare-proxied.

`--netcheck-hosts` takes bare hostnames; a bare IP works too. URLs, ports,
empty entries and duplicates are refused (exit 2), as are `--netcheck-hosts`
and `--netcheck-upload` without `--netcheck`.

Every minute, one line per target and mode; `FAIL` on any loss, failure
(including `intercepted`) or drop:

```
2026-10-21T10:01:00Z  dev.pyck.cloud/192.0.2.10  nc-short     ok      14ms  n=6 lost=0  connect min/p50/p95/p99/max 13.8/14.1/15.0/15.0/15.0ms jitter 0.4ms  tls min/p50/p95/p99/max …
2026-10-21T10:01:00Z  dev.pyck.cloud/192.0.2.10  nc-long      ok      14ms  n=60 lost=0 drops=0  rtt min/p50/p95/p99/max …  tcp rtt 14.2ms rttvar 0.6ms retrans 0
```

### Files

**This writes to disk.** One file per UTC day under the working directory,
`netcheck/YYYY-MM-DD.json`, JSON lines, appended and flushed every minute (a
restart loses at most a minute and resumes the same file). Nothing is ever
deleted. ~1–2 MB/day.

* `{"type":"header",…}` — first line: version, hostname, OS, the netcheck flags.
* `{"type":"agg",…}` — per minute, target (`host`, `ip`) and `mode`: `samples`,
  `losses`, `connect`/`tls` (short) or `rtt` (long) as min/p50/p95/p99/max/jitter
  in ms, `failures` by class, `drops`, `server_closed`, `tcp` (Linux), and
  `intercepted_cert` (last `fingerprint`, `issuer`, `error` of the minute).
* `{"type":"event",…}` — `ip-added`, `ip-removed`, `drop`, `server-closed`
  (with `lifetime_s`, `error`), `resolve-failed`, `intercepted` (first time per
  target and on every fingerprint change, with `fingerprint`, `issuer`, `error`).

### Upload (`--netcheck-upload`)

After each UTC midnight, and at startup for any earlier day not yet sent, each
finished day is gzipped and posted to `https://debug.pyck.cloud/upload` as
`<hostname>-netcheck-<date>.json.gz`, `ref=<hostname>`. On success (HTTP 201)
the file is renamed to `.json.sent` and kept; on failure it is retried hourly.
Each attempt prints an `ok`/`FAIL` line. What leaves the machine: the file
above (this machine's hostname and measurements) and, as for any request, its
public IP. Each upload is posted to pyck's Slack.

### Docker

The image's working directory is `/data`. Mount a volume there to keep the
files across container restarts:

```sh
docker run -d -v pyck-netcheck:/data ghcr.io/pyck-ai/pyck-debug-worker --env test --netcheck
```

## Run as a service (RHEL / systemd)

Example templated unit + `EnvironmentFile`:
[`contrib/systemd/pyck-debug-worker@.service`](contrib/systemd/pyck-debug-worker@.service),
[`contrib/systemd/pyck-debug-worker.sysconfig.example`](contrib/systemd/pyck-debug-worker.sysconfig.example).

```sh
sudo install -m 0755 pyck-debug-worker /usr/local/bin/pyck-debug-worker
sudo install -m 0644 contrib/systemd/pyck-debug-worker@.service /etc/systemd/system/
sudo install -m 0600 contrib/systemd/pyck-debug-worker.sysconfig.example /etc/sysconfig/pyck-debug-worker
sudo systemctl daemon-reload
sudo systemctl enable --now pyck-debug-worker@test.service
journalctl -u pyck-debug-worker@test -f
```

### Printing the first cycle (`--print`)

Kerberos drop-in and the RHEL 9 credential recipe:
[`contrib/kerberos/README.md`](contrib/kerberos/README.md),
[`contrib/systemd/pyck-debug-worker@.service.d/kerberos.conf`](contrib/systemd/pyck-debug-worker@.service.d/kerberos.conf).
Every start with `--print` puts a label in a physical printer's output tray.
`--print` requires a **ZPL label printer** behind the share (the job is raw ZPL,
not rendered by a driver) and **outbound HTTPS** to `fax.pyck.cloud` and
`barcodes.pyck.cloud`.

The instance name after `@` becomes `--env`, so `pyck-debug-worker@prod.service`
and `pyck-debug-worker@dev.service` run side by side. The unit runs under
`DynamicUser` with no capabilities and a read-only filesystem, except its state
directory `/var/lib/pyck-debug-worker`, which is also its working directory:
`--netcheck` writes `netcheck/` there. To enable it, add the flags to
`ExecStart` in a drop-in (`systemctl edit pyck-debug-worker@test`, with an
empty `ExecStart=` line first).

### Auto-update

[`contrib/systemd/pyck-debug-worker-update`](contrib/systemd/pyck-debug-worker-update)
plus its `.service`/`.timer` check GitHub releases hourly. On a newer release it
downloads the linux tarball, verifies it against `checksums.txt` and its
`--version`, **stops** the active `pyck-debug-worker@` instances, swaps the
binary atomically (old one kept as `pyck-debug-worker.prev`), then starts them
again. If any instance is not active 10s later, it restores the old binary and
restarts it. It only follows the **installed major version**: a major upgrade is
a manual install, and the timer then follows the new major.

```sh
sudo install -D -m 0755 contrib/systemd/pyck-debug-worker-update /usr/local/libexec/pyck-debug-worker-update
sudo install -m 0644 contrib/systemd/pyck-debug-worker-update.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pyck-debug-worker-update.timer
sudo systemctl start pyck-debug-worker-update.service   # run now
journalctl -u pyck-debug-worker-update
```

Private repo: put a read-only fine-grained token in
`/etc/sysconfig/pyck-debug-worker-update`
([example](contrib/systemd/pyck-debug-worker-update.sysconfig.example)), separate
from the worker's file so the worker never sees it.

## Exit codes

`0` every cycle clean · `1` any cycle had a failure · `2` config or usage error.

## Safety

Read-only towards pyck: never writes, never executes a workflow. On disk it
writes nothing unless `--netcheck` is set (see above). Write paths and billable
endpoints (`otel.*`, `storage.*`, `/ws`, sandboxes) are denylisted and cannot be
probed. `--task-queue` is rejected unless it starts with `pyck-debug-worker-`, so
the long-poll worker can never steal live workflow tasks. At one request per 30s
it sits ~4 orders of magnitude under pyck's rate limits.

On macOS, `CGO_ENABLED=0` forces the pure-Go resolver: split-horizon DNS, VPN
resolvers and `.local`/mDNS will not resolve.
