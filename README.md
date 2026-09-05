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
pyck-debug-worker --target 127.0.0.1:7233=grpc --insecure --namespace default --deep
```

`--env` resolves both the Temporal frontend and the app domain. Note `prod` is
`eu.pyck.cloud`, and `feature/<branch>` uses a `-` separator.

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
| `--target` | explicit `host:port[=grpc\|https]`, repeatable |
| `--interval` | cycle interval, default `30s` |
| `--namespace` | Temporal namespace |
| `--insecure` | plaintext, no credentials (in-cluster `:7236`) |
| `--deep` | enable the long-poll stage |
| `--task-queue` | default `pyck-debug-worker-probe` |
| `--ca-bundle` | PEM CA bundle |
| `--token-file` | file holding a credential |
| `--debug-dns` | capture the Go resolver's decision trace |
| `--version` | |

## Exit codes

`0` every cycle clean · `1` any cycle had a failure · `2` config or usage error.

## Safety

Read-only. Never writes, never executes a workflow. Write paths and billable
endpoints (`otel.*`, `storage.*`, `/ws`, sandboxes) are denylisted and cannot be
probed. `--task-queue` is rejected unless it starts with `pyck-debug-worker-`, so
the long-poll worker can never steal live workflow tasks. At one request per 30s
it sits ~4 orders of magnitude under pyck's rate limits.

On macOS, `CGO_ENABLED=0` forces the pure-Go resolver: split-horizon DNS, VPN
resolvers and `.local`/mDNS will not resolve.
