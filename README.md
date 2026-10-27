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
of every host (resolved at startup and every 5 min) is one target, measured
these ways:

* **short** — every 10s a fresh TCP connect + TLS handshake, then close. No
  HTTP request is sent. Records connect and handshake time; failures are
  `timeout`, `refused`, `reset`, `intercepted` or `other`; a connect taking ≈1s
  or ≈3s counts as a lost SYN. For a hostname, every other handshake sends **no
  SNI**, and outcomes are counted per variant (`host`, `none`), so SNI-based
  blocking shows as only the `host` variant failing. The no-SNI handshake has
  no name to verify and is never counted as `intercepted`.
* **long** — one HTTP/2 connection, PING every 1s. Records PING RTT, unanswered
  PINGs (5s), drops with lifetime and error, and on Linux the kernel's `TCP_INFO`
  (rtt, rttvar, retransmits). A server GOAWAY (e.g. nginx `keepalive_time`) is
  `server-closed`, not a drop. No PING answered for 30s is a drop. Reconnects
  with backoff.
* **idle** — a third HTTP/2 connection, without TCP keepalives, pinged once and
  then after silent gaps of 30s, 1, 2, 5, 10 and 30 min (then every 30 min).
  Records the longest gap the connection survived and how it died: `timeout`
  (no answer in 30s), `reset`, `other`, or `server-closed` (GOAWAY, not a
  failure). Reconnects and starts over from 30s.
* **throughput** — at startup and every 15 min, `GET
  https://<host>/static/netcheck/1m.bin` over a fresh connection to the target's
  IP, `Accept-Encoding: identity`, one download at a time across all targets.
  Records TTFB, Mbit/s and the longest stall between reads. Anything but 200
  with exactly 1,048,576 bytes fails (`status`, `size`); the `Server` header and,
  for an HTML body, a short block-page hint (its title) are kept. **~100 MB/day
  per target.**
* **trace** (Linux only) — at startup, hourly, and when the long connection's
  p50 RTT rises more than 30% and at least 10ms over the previous minute (at
  most every 10 min): a `tracepath`-style trace, unprivileged (UDP probes,
  ICMP errors from the socket's error queue), every probe to a target on the
  same UDP flow so load-balanced paths do not look like route changes. Records every hop's IP and RTT,
  tags the CN2 (`59.43/16`), ChinaNet (`202.97/16`), China Unicom AS4837
  (`219.158/16`) and China Mobile (`223.120/15`) backbones, and the path MTU. A
  hop IP different from the previous trace is a `route-changed` event. Most
  destinations drop UDP, so `not-reached` is normal.

Resets are counted by when they arrived: `hello` (before the server answered
the ClientHello — the signature of SNI filtering), `transfer` (while data was
flowing) and `idle` (first PING after an idle gap).

Per host, after every 5-minute resolution, a **DNS check** asks AliDNS
(`223.5.5.5`) and Cloudflare (`1.1.1.1`) over DNS-over-HTTPS (RFC 8484 GET,
wire format, certificate verified, never via a proxy) and compares their A
records with the system resolver's. Not done for a bare IP.

Once per process, **compare** connects to `223.5.5.5:443` (inside China) and
`1.1.1.1:443` (outside) every 10s, TCP only, to tell a bad local network from a
bad border crossing.

TLS uses the host as SNI and **verifies the certificate** for it against the
system roots. A handshake that presents a certificate failing verification is
`intercepted` (a TLS-inspecting middlebox, or a broken server certificate): the
leaf's SHA-256 fingerprint, issuer CN and the verification error are recorded,
the short connection's handshake time still counts, and the long and idle
connections are not used for PINGs. The throughput download goes ahead on an
intercepted connection, so a block page behind it is seen, but fails. A bare-IP
entry has no name to verify: no SNI, no verification, `Host` is the IP. Hosts
must not be Cloudflare-proxied.

`--netcheck-hosts` takes bare hostnames; a bare IP works too. URLs, ports,
empty entries and duplicates are refused (exit 2), as are `--netcheck-hosts`
and `--netcheck-upload` without `--netcheck`.

Every minute, one line per target and mode (`nc-short`, `nc-long`, `nc-idle`)
and per comparison target (`nc-compare`); `FAIL` on any loss, failure
(including `intercepted`) or drop. Throughput, trace and DNS check print one
line each time they run (`nc-tput`, `nc-trace`, `nc-dns`):

```
2026-10-22T07:10:00Z  dev.pyck.cloud/192.0.2.10  nc-short     ok      49ms  n=6 lost=0  sni ok host 3/3 none 3/3  connect min/p50/p95/p99/max 42.6/48.8/56.9/56.9/56.9ms jitter 4.9ms  tls min/p50/p95/p99/max …
2026-10-22T07:10:00Z  dev.pyck.cloud/192.0.2.10  nc-long      ok      57ms  n=60 lost=0 drops=0  rtt min/p50/p95/p99/max …  tcp rtt 53.0ms rttvar 7.6ms retrans 3
2026-10-22T07:10:00Z  dev.pyck.cloud/192.0.2.10  nc-idle      ok      48ms  n=1 lost=0 drops=0  rtt min/p50/p95/p99/max …  survived 60s
2026-10-22T07:12:00Z  dev.pyck.cloud/192.0.2.10  nc-idle      ok      47ms  n=2 lost=0 drops=0 server-closed=1  rtt min/p50/p95/p99/max …  survived 30s  died after 120s gap: server-closed (had survived 60s)
2026-10-22T07:10:00Z  alidns/223.5.5.5           nc-compare    ok      54ms  n=6 lost=0  connect min/p50/p95/p99/max 51.8/54.5/65.1/65.1/65.1ms jitter 5.2ms
2026-10-22T07:08:47Z  dev.pyck.cloud             nc-dns       ok     140ms  system 192.0.2.10 139.6ms  alidns 192.0.2.10 342.1ms  cloudflare 192.0.2.10 342.5ms
2026-10-22T07:08:47Z  dev.pyck.cloud/192.0.2.10  nc-tput      ok     1.49s  status 200 HTTP/2.0  1048576 B 7.25 Mbit/s  connect 73.9ms tls 111.1ms ttfb 144.1ms stall 185.1ms  server "nginx"
2026-10-22T07:08:47Z  dev.pyck.cloud/192.0.2.10  nc-trace     ok    24.63s  startup  hops=14  reached  pmtu=1280
```

### Files

**This writes to disk.** One file per UTC day under the working directory,
`netcheck/YYYY-MM-DD.json`, JSON lines, appended and flushed every minute (a
restart loses at most a minute and resumes the same file). Nothing is ever
deleted. Measured with three hosts and `--env test`: ~15 MB/day (more than half
of it probe results), ~1.7 MB/day gzipped as uploaded.

* `{"type":"header",…}` — first line: version, hostname, OS, the netcheck flags.
* `{"type":"agg",…}` — per minute, target (`host`, `ip`) and `mode` (`short`,
  `long`, `idle`, `compare`): `samples`, `losses`, `connect`/`tls` (short,
  compare) or `rtt` (long, idle) as min/p50/p95/p99/max/jitter in ms, `failures`
  by class, `drops`, `server_closed`, `tcp` (Linux), `intercepted_cert` (last
  `fingerprint`, `issuer`, `error` of the minute), `resets` by phase, `sni`
  (short: `host`/`none` → `samples`, `failures`), and `idle` (`survived_s`, the
  longest gap the current connection survived; `died`: `gap_s`, `survived_s`,
  `how`). Comparison targets have `host` `alidns` or `cloudflare`.
* `{"type":"throughput",…}` — per download: `ok`, `status`, `proto`, `bytes`,
  `connect_ms`, `tls_ms`, `ttfb_ms` (request written → first byte), `body_ms`,
  `mbit_s`, `stall_ms`, `server`, `block_hint`, `class`/`phase`/`error` when it
  failed, `intercepted_cert`.
* `{"type":"trace",…}` — per trace: `reason` (`startup`, `hourly`,
  `latency-jump`), `hops` (`ttl`, `ip`, `rtt_ms`, `carrier`; no `ip` for a silent
  TTL), `reached`, `pmtu`, `duration_ms`, `route_changed`, `error`.
* `{"type":"dns",…}` — per host and check: `answers` (`resolver` `system`,
  `alidns` or `cloudflare`, `ms`, sorted `ips`, `nxdomain`, or `error`/`class`
  when it could not be asked), `mismatch`, `unreachable`.
* `{"type":"probe",…}` — every `--env` probe stage result: `ts`, `target`,
  `stage`, `ok`, `duration_ms`, `detail` — the printed line, which never carries
  a secret.
* `{"type":"event",…}` — `ip-added`, `ip-removed`, `drop`, `server-closed`
  (with `mode`, `lifetime_s`, `error`; a drop's `class` and a reset's `phase`;
  for `idle` also `gap_s` and `survived_s`, absent meaning 0),
  `resolve-failed`, `intercepted` (first time per target and on every
  fingerprint change, with `fingerprint`, `issuer`, `error`), `dns-mismatch`
  (`answers` per resolver), `resolver-unreachable` (`resolver`, `class`,
  `error`), `route-changed` (`path`, `prev_path`, `*` for a silent TTL).

### Field reference

Every line of `netcheck/YYYY-MM-DD.json` is one JSON object with a `type`.
Conventions:

* `ts` is UTC RFC 3339; an `agg` `ts` is the start of its minute, other records
  carry fractional seconds.
* Units are in the name: `_ms` milliseconds, `_s` seconds, `mbit_s` megabit/s.
  Latencies are rounded to microseconds.
* Percentiles are nearest-rank over the minute's samples. `jitter_ms` is the
  mean absolute difference between consecutive samples in arrival order (0 for
  one sample).
* **A missing field means none**: empty strings, zeros, `false` and empty lists
  are omitted where the tables say so. Always-present fields are listed as such.
* IPs are IPv4 strings. Failure classes: `timeout`, `refused`, `reset`, `other`,
  `intercepted`; a download adds `status`, `size`. Reset phases: `hello`,
  `transfer`, `idle`.

**`header`** — first line of each file (a restart appends, no second header).

| field | type | |
|---|---|---|
| `version`, `hostname`, `os` | string | always; `os` is `GOOS/GOARCH` |
| `flags.hosts` | string[] | always |
| `flags.upload` | bool | always |

**`agg`** — one per minute, target and `mode`. Always present: `host`, `ip`,
`mode`, `samples`, `losses`, `drops`. Comparison targets have `host` `alidns` or
`cloudflare`.

| field | type | present |
|---|---|---|
| `samples` | int | all modes: connects (short, compare), answered + unanswered PINGs (long, idle). Failed short/compare connects count too |
| `losses` | int | SYN retransmits inferred from a 1s/3s connect (short, compare); unanswered PINGs (long, idle) |
| `drops` | int | connections that died (long, idle); always 0 for short, compare |
| `connect`, `tls`, `rtt` | stats object | when the minute has such samples: `connect` (short, compare), `tls` (short), `rtt` (long, idle). Object: `min_ms`, `p50_ms`, `p95_ms`, `p99_ms`, `max_ms`, `jitter_ms` |
| `failures` | {class: int} | when any failure; includes `intercepted` |
| `server_closed` | int | when > 0 (long, idle): server GOAWAY, not a drop |
| `tcp` | {`rtt_ms`, `rttvar_ms`, `retrans`} | long only, Linux only (`TCP_INFO`, last reading; `retrans` counted in the minute) |
| `intercepted_cert` | {`fingerprint`, `issuer`, `error`} | only when the minute had an interception (last one); `fingerprint` is hex SHA-256 of the leaf |
| `resets` | {phase: int} | when any reset (short, long, idle) |
| `sni` | {`host`/`none`: {`samples`, `failures`}} | short, hostname targets only (not bare IPs); `samples` includes failures, `failures` omitted when none |
| `idle` | {`survived_s`, `died`} | idle only, always. `survived_s`: longest gap the current connection survived (0 on a fresh one). `died`, when a connection ended this minute: `gap_s` (gap after which the PING failed, 0 = first PING), `survived_s`, `how` (`timeout`, `reset`, `other`, `server-closed`) |

**`event`** — always `ts`, `event`, `host`; `ip` unless the event is about the
host as a whole.

| `event` | extra fields (all omitted when empty/0) |
|---|---|
| `ip-added`, `ip-removed` | — |
| `drop` | `mode` (`long`/`idle`), `lifetime_s`, `error`, `class` (`timeout`/`reset`/`other`), `phase` (only for a reset); idle also `gap_s`, `survived_s` |
| `server-closed` | `mode`, `lifetime_s`, `error`; idle also `gap_s`, `survived_s` |
| `resolve-failed` | `error` (no `ip`) |
| `intercepted` | `mode` (`short`/`long`/`idle`/`throughput`), `fingerprint`, `issuer`, `error`; first time per target and on each fingerprint change |
| `dns-mismatch` | `answers`: {resolver: ip[]} for resolvers that answered (no `ip`) |
| `resolver-unreachable` | `resolver`, `class`, `error` (no `ip`) |
| `route-changed` | `path`, `prev_path`: hop IPs by TTL, `*` for a silent TTL |

**`dns`** — per host and 5-minute check. Always: `host`, `answers`, `mismatch`.

| field | type | |
|---|---|---|
| `answers[]` | object | `system`, `alidns`, `cloudflare`, in that order |
| `answers[].resolver`, `.ms`, `.ips` | string, ms, string[] | always; `ips` sorted, `[]` if none |
| `answers[].nxdomain` | bool | only if the name does not exist |
| `answers[].error`, `.class` | string | only if the resolver could not be asked |
| `mismatch` | bool | resolvers that answered disagree on the A set |
| `unreachable` | string[] | resolvers that could not be asked; omitted when none |

**`throughput`** — per download. Always: `host`, `ip`, `ok`, `bytes`.

| field | type | omitted when |
|---|---|---|
| `ok` | bool | — (true = 200 and exactly 1,048,576 bytes) |
| `status`, `proto` | int, string (`HTTP/2.0`) | no response |
| `bytes` | int | — (body bytes read, capped at 1 MiB + 1) |
| `connect_ms`, `tls_ms` | ms | not measured |
| `ttfb_ms` | ms | request written → first response byte |
| `body_ms`, `mbit_s`, `stall_ms` | ms, Mbit/s, ms | first byte → end of body; speed over `body_ms`; longest wait between reads |
| `server` | string | no `Server` header |
| `block_hint` | string | `ok`, or the body does not look like HTML; else its title (`Web Filter: …` when it mentions one) |
| `class`, `phase`, `error` | string | `ok`; `phase` only for a reset |
| `intercepted_cert` | as in `agg` | certificate verified fine |

**`trace`** — Linux only, per trace. Always: `host`, `ip`, `reason`, `hops`,
`reached`, `duration_ms`.

| field | type | |
|---|---|---|
| `reason` | string | `startup`, `hourly`, `latency-jump` |
| `hops[]` | object | `ttl` (always); `ip`, `rtt_ms` omitted for a silent TTL; `carrier` (`CN2`, `ChinaNet`, `Unicom-AS4837`, `ChinaMobile`) only for a tagged IP |
| `reached` | bool | the destination itself answered |
| `pmtu` | int | omitted when unknown |
| `route_changed` | bool | only when true: a hop IP differs from the previous trace (silent TTLs match anything) |
| `error` | string | only when the trace failed |

**`probe`** — one per `--env` probe stage result, as printed.

| field | type | |
|---|---|---|
| `ts`, `target`, `stage`, `ok`, `duration_ms` | | always |
| `detail` | string | omitted when empty |

`jq` examples:

```sh
F=netcheck/2026-10-22.json
# p95 PING RTT per minute and host/IP
jq -r 'select(.type=="agg" and .mode=="long" and .rtt) | [.ts,.host,.ip,.rtt.p95_ms] | @tsv' $F
# minutes with any loss, drop or failure
jq -c 'select(.type=="agg" and (.losses>0 or .drops>0 or .failures!=null)) | {ts,host,ip,mode,losses,drops,failures}' $F
# throughput history
jq -r 'select(.type=="throughput") | [.ts,.host,.ok,.mbit_s,.ttfb_ms,.stall_ms,.class//""] | @tsv' $F
```

### Upload (`--netcheck-upload`)

After each UTC midnight, and at startup for any earlier day not yet sent, each
finished day is gzipped and posted to `https://debug.pyck.cloud/upload` as
`<hostname>-netcheck-<date>.json.gz`, `ref=<hostname>`. On success (HTTP 201)
the file is renamed to `.json.sent` and kept; on failure it is retried hourly.
Each attempt prints an `ok`/`FAIL` line. What leaves the machine: the file
above (this machine's hostname, measurements and probe results) and, as for any
request, its public IP. Each upload is posted to pyck's Slack.

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

### Enabling netcheck on the service

`sudo systemctl edit pyck-debug-worker@test` (writes
`/etc/systemd/system/pyck-debug-worker@test.service.d/override.conf`); the empty
`ExecStart=` clears the base unit's command first. `%i` is the instance name:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/pyck-debug-worker --env %i --netcheck --netcheck-hosts=region-sing.pyck.cloud,region-japan.pyck.cloud
```

With the daily upload to `debug.pyck.cloud` (see [Upload](#upload---netcheck-upload)):

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/pyck-debug-worker --env %i --netcheck --netcheck-upload --netcheck-hosts=region-sing.pyck.cloud,region-japan.pyck.cloud
```

```sh
sudo systemctl daemon-reload && sudo systemctl restart pyck-debug-worker@test
```

The day files are in `/var/lib/pyck-debug-worker/netcheck/YYYY-MM-DD.json`
(sent days are renamed `….json.sent`). The unit runs as a dynamic user and the
directory is not world-readable, so read as root:

```sh
sudo ls -l /var/lib/pyck-debug-worker/netcheck/
sudo jq -c 'select(.type=="event")' /var/lib/pyck-debug-worker/netcheck/$(date -u +%F).json
journalctl -u pyck-debug-worker@test -f | grep ' nc-'   # the per-minute lines
```

All instances share that directory: enable netcheck on one instance per host.

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
plus its `.service`/`.timer` check GitHub releases hourly. On a newer release on
its channel (below) it
downloads the linux tarball, verifies it against `checksums.txt` and its
`--version`, **stops** the active `pyck-debug-worker@` instances, swaps the
binary atomically (old one kept as `pyck-debug-worker.prev`), then starts them
again. If any instance is not active 10s later, it restores the old binary and
restarts it. It only follows the **installed major version**: a major upgrade is
a manual install, and the timer then follows the new major.

`Environment=UPDATE_CHANNEL=` in the `.service` picks what it follows, and is
the only line that differs between servers: `test` takes pre-releases
(`vX.Y.Z-rc.N`), `prod` (the shipped default) releases (`vX.Y.Z`). A pre-release
sorts before its release, so `v1.6.0` replaces `v1.6.0-rc.3`. On a test server,
change the line in `/etc/systemd/system/pyck-debug-worker-update.service` before
enabling the timer.

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
