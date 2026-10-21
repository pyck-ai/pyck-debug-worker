# netcheck — long-term network quality plan

Goal: measure RTT and connection quality from remote sites (primarily mainland
China → Singapore) to every pyck ingress location, over days, and ship the
results to `debug.pyck.cloud` for analysis.

The typical failure on that route is not high average latency. It is:

* evening collapse (~19:00–23:00 China time): bandwidth drops, loss climbs, RTT looks fine;
* sudden switch to a worse carrier route;
* Great Firewall interference: forged resets, SNI-based blocking, forged DNS answers;
* middleboxes silently killing idle connections.

## Flags

* **`--netcheck`** — measure, write results to disk.
* **`--netcheck-upload`** — additionally upload finished days to `debug.pyck.cloud`.
  Refused (exit 2) unless `--netcheck` is also set.
* **`--netcheck-hosts <h1,h2,…>`** — comma-separated hosts to measure, all at once,
  e.g. `--netcheck-hosts=region-sing.pyck.cloud,region-japan.pyck.cloud`.
  Default `dev.pyck.cloud`. Refused (exit 2) unless `--netcheck` is also set.
  Hostnames are expected. A bare IP is accepted but name-based checks are skipped
  for it (see Locations). Full URLs, empty entries and duplicates are refused (exit 2).
* Everything else is a fixed constant (intervals, upload URL).
* `--env` stays required; with both flags off, behaviour is unchanged.

## Locations

* Each host is one location (a pyck frontend or a dedicated endpoint VM), handed out
  per site via `--netcheck-hosts`. No ingress changes.
* All hosts are measured concurrently and independently. A measurement target is
  a (host, IP) pair; every record, stdout line and aggregate carries both.
* All A records of each host are measured. Resolve at startup and every 5 min.
  New IP → start measuring. Removed IP → stop, keep its data.
* **Bare IP entry:** measured as a single target, no resolve loop.
  Skipped: DNS check (7), SNI alternation (4: no SNI, Host header = the IP).
  Everything else runs. The intended use is a real hostname.
* Every connection uses the host as TLS SNI and HTTP `Host`, so nginx routes it
  exactly like real traffic, including the throughput download.
* The host must not be Cloudflare-proxied, otherwise we measure Cloudflare.
  All `*.pyck.cloud` hosts are DNS at Cloudflare but unproxied, so any of them
  works (`dev.pyck.cloud` → `128.140.28.237`, nginx direct).

## Measurements (per host+IP target unless noted)

| # | What | How | Frequency |
|---|------|-----|-----------|
| 1 | Short connections | Fresh TCP connect + TLS handshake + close. No HTTP request sent (nothing in access logs). Record connect/handshake time; failures classified (timeout/refused/reset). Connect ≈1s/3s counted as SYN-retransmit (loss signal). | 10s |
| 2 | Long connection | One HTTP/2 connection (`golang.org/x/net/http2`), HTTP/2 PING every 1s. Record ping RTT, unanswered pings, every drop (lifetime + error). Linux: `TCP_INFO` (rtt, rttvar, retransmits). Reconnect with backoff. nginx `keepalive_time` (default 1h) closes are logged as `server-closed`, not drops. | 1s |
| 3 | Idle survival | Third connection pinging after growing gaps (30s, 1, 2, 5, 10, 30 min); record longest surviving gap and how it died. Matters for Temporal 60s long-polls / gRPC streams. | continuous |
| 4 | Firewall fingerprints | Short connections alternate TLS SNI between `<host>` and none. Classify resets by timing (right after ClientHello / mid-transfer / idle). | every short conn |
| 5 | Throughput | GET `https://<host>/static/netcheck/1m.bin`, dialled to each IP (exactly 1 MiB, uncompressed). Record TTFB, speed, longest stall. Any response ≠ 1,048,576 bytes = failed measurement. ~100 MB/day per target. | 15 min |
| 6 | Route trace | Hop-by-hop, `tracepath`-style (unprivileged), Linux only. Per-hop IP + RTT, tag carrier ranges (CN2 `59.43.*`, CT `202.97.*`, Unicom AS4837, Mobile). "Route changed" event. Also catches MTU issues. | hourly + on latency jump |
| 7 | DNS check (per host) | Resolve each host via system resolver, AliDNS DoH (`223.5.5.5`), Cloudflare DoH (`1.1.1.1`). Record mismatches and unreachable resolvers. | 5 min |
| 8 | Comparison targets (global) | TCP connect only, no data: `223.5.5.5:443` (inside China), `1.1.1.1:443` (outside). Separates "local network bad" from "border crossing bad". | 10s |
| 9 | Persist probes | With `--netcheck`, also write each 30s `--env` probe result into the daily file. | per cycle |

TLS: SNI as above, certificate not verified (only handshakes, HTTP/2 PINGs and the
payload travel; cert checking is the `--env` probes' job).

Not doing: ICMP ping (needs raw sockets; unit drops all privileges), HTTP/3.
The uploader's ISP is derivable from the IP `debug.pyck.cloud` already records.

## Aggregation

Raw samples are not stored (~100 MB/day). Every minute, per target and mode:
samples, losses, min/p50/p95/p99/max, jitter, failures by type, drops.

## Stdout

One summary line per target per minute in the existing `ok`/`FAIL` format. A minute is
`FAIL` on any loss, failure or drop. Netcheck results never affect the exit code.
Runs in its own goroutine under the existing signal-cancelled context, separate
from the 30s probe cycle.

## On disk

* Directory: `netcheck/` under the working directory, one file per UTC day
  (`netcheck/2026-10-19.json`).
* JSON lines: per-minute aggregates and events (IP added/removed, drop, route change).
* Header per file: version, hostname, OS, flags.
* Appended and flushed every minute (restart/auto-update loses ≤1 min).
* Without `--netcheck-upload`, files stay; nothing is deleted.
* Expected size: ~1–2 MB/day uncompressed (mostly route traces), <1 MB gzipped.

## Upload

* Receiver exists: `debug-dropbox` — `POST https://debug.pyck.cloud/upload?name=…&ref=…`,
  no auth, `json,gz,…` up to 100 MB, posts each upload to Slack. No server changes.
* Once per day after UTC midnight, send each finished day gzipped:
  `name=<host>-netcheck-<date>.json.gz&ref=<hostname>`.
* Success = HTTP 200 and `ok:true`; then rename to `.sent` (kept).
* Failure: retry hourly. Unsent finished days are sent at startup.
* Each attempt prints an `ok`/`FAIL` line. Reuse the post-and-check pattern from
  `printcheck/print.go`.
* Uploaded: hostname and public IP (already logged by the dropbox).
* One Slack message per worker per day.

## Code layout

New package `internal/netcheck`:

* `resolve.go` — resolver loop, DNS check
* `short.go`, `long.go`, `idle.go` — connection modes
* `throughput.go` — payload download
* `trace.go` — route tracing (Linux), stub elsewhere
* `tcpinfo_linux.go`, `tcpinfo_other.go`
* `agg.go` — per-minute aggregation
* `store.go` — daily files
* `upload.go` — daily upload

`main.go`: two flags, startup check, banner line, goroutine.

Tests: aggregation maths; day rotation and resume after restart; upload success/failure
(httptest); short/long modes against local listeners incl. one that kills the
connection; flag validation.

## Deployment changes

* **systemd unit** (`DynamicUser`, `ProtectSystem=strict` → currently cannot write):
  add `StateDirectory=pyck-debug-worker` and `WorkingDirectory=%S/pyck-debug-worker`
  (`/var/lib/pyck-debug-worker`), keeping the sandbox.
* **Docker:** add `WORKDIR` + volume note in README.
* **README:** "never writes to disk" no longer true with `--netcheck`; document both
  flags, file format, what is uploaded.

## Singapore endpoint VM

Dedicated measurement target for the China → Singapore path.

* Small Hetzner VM in Singapore, with its own hostname, e.g. `sg-netcheck.pyck.cloud`:
  A record at Cloudflare, unproxied. Sites run e.g. `--netcheck-hosts=sg-netcheck.pyck.cloud,<other regions>`.
* Same setup applies to any further region VM (e.g. Japan).
* nginx with TLS (self-signed is enough: the worker does not verify certificates;
  Let's Encrypt optional) and HTTP/2 enabled (`listen 443 ssl; http2 on;`).
* `location = /static/netcheck/1m.bin` serves the 1 MiB file from the frontend repo
  (`apps/pyck/public/static/netcheck/1m.bin`), uncompressed (`gzip off`). Everything
  else returns 404.
* `keepalive_timeout 1h` (default 75s would kill idle-survival gaps); `keepalive_time`
  default (1h) is fine, the worker logs it as `server-closed`.
* Config and install steps: `contrib/netcheck-host/`.
* Open port 443 only.

## Dependencies / status

* **Payload — done:** frontend PR #1129 adds
  `apps/pyck/public/static/netcheck/1m.bin` (1 MiB random). Served at
  `https://<location>/static/netcheck/1m.bin` after a frontend deploy. Under `/static/`
  nginx uses `try_files $uri =404`, so a missing file is a real 404, not the SPA's
  `index.html`. Local commit: worktree `frontend@netcheck-payload` (`6e5f24ad`).
  Its `audit` CI check fails on advisories already on `main` (not the PR):
  `@modelcontextprotocol/sdk` 1.31.0→1.32.0, `launch-editor` 2.14.1→2.14.2,
  `vite` 8.3.2→8.3.3. A separate dependency-bump PR is needed first; then rebase.
  Merged since: `https://dev.pyck.cloud/static/netcheck/1m.bin` returns 200,
  1,048,576 bytes, HTTP/2 (checked 2026-10-21).
* Other hosts serve the payload only after their frontend deploy.

## Delivery

Branch `u/max/netcheck`, `feat(netcheck)` PRs in this order:

1. Core: resolver, short connections, long connections, daily files, upload,
   systemd unit + docs.
2. Idle survival (3) + firewall fingerprints (4).
3. DNS check (7) + comparison targets (8).
4. Throughput (5).
5. Route tracing (6).
6. Persist probes (9).

Verify against a local stub server and against `dev.pyck.cloud`.
