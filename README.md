# CheeseWAF Adapters

Go-first, self-hosted gateway adapters for [CheeseWAF](https://github.com/LaokeQwQ/CheeseWAF).

This repository keeps gateway-specific glue code separate from the CheeseWAF detection engine. The default integration is a local Go process (`adapterd`) that translates gateway metadata into a versioned inspection contract and maps the core decision back to the gateway.

[简体中文](README_CN.md)

## Status

The repository currently contains the contract and a small, testable `adapterd` skeleton. NGINX `auth_request` and Envoy HTTP authorization examples are included. The core endpoint is deliberately explicit; the adapter does not silently allow traffic when the core URL is missing or unavailable.

## Design principles

- **Self-hosted:** no required SaaS control plane, telemetry endpoint, or vendor account.
- **Go-first:** the daemon, contract, tests, and future sidecar controller stay in Go.
- **Sidecar-first:** use a local process beside the gateway or workload; shared deployment is optional.
- **Thin adapters:** gateway packages translate protocol context and enforce response semantics. Detection, policy, storage, and ALAP remain in CheeseWAF.
- **Inline and out-of-band are separate:** inline authorization may block; mirror-based observation must never be advertised as blocking.
- **Fail-closed by default:** an unavailable core returns `503 Service Unavailable`. Operators may opt into fail-open explicitly.
- **Body minimization:** request bodies are not forwarded by default and require an explicit policy decision.
- **Production dependency boundary:** adapterd packages and images contain only runtime dependencies required by the published adapter contract. Development assistants, editor integrations, and local inspection tooling are excluded from production artifacts.

## Architecture

    NGINX / Envoy / Kubernetes gateway
                  |
                  | auth_request / ext_authz / ext_proc
                  v
    CheeseWAF-Adapters (adapterd, Go)
                  |
                  | versioned HTTP contract
                  v
    CheeseWAF core (self-hosted, Go)
                  |
                  +-- inline decision
                  +-- asynchronous telemetry / postanalytics

The public repository contains the two README files, source code, and runnable integration examples. Internal planning notes and local Agent policy stay in the operator workspace; chat transcripts, credentials, runtime state, and private artifacts are excluded by `.gitignore`.

## Integration scope

`adapterd` currently provides the client-side contract and gateway boundary. The CheeseWAF core does not yet ship the matching inspection and telemetry endpoints, so end-to-end use requires a compatible core endpoint or a separate mock; this repository must not be presented as a completed CheeseWAF integration. Future transports and cross-cluster analytics require separately versioned contracts and tests, remain optional, and stay outside the inline authorization path.

## Quick start

Requirements: Go 1.26.6 or newer.

    go test ./...
    go run ./cmd/adapterd --listen 127.0.0.1:9080 --core-url http://127.0.0.1:8080

Health endpoints:

    curl -i http://127.0.0.1:9080/healthz
    curl -i http://127.0.0.1:9080/readyz

The adapter calls the configured core inspection endpoint (default path: `/api/v1/adapter/inspect`) and probes `/healthz` for `readyz`. Override the paths with `CHEESEWAF_CORE_INSPECT_PATH` and `CHEESEWAF_CORE_HEALTH_PATH` when the core exposes different routes. These `/api/v1/adapter/*` paths, not the older `/api/v1/check` name, are the canonical adapter contract.

## Gateway examples

- NGINX metadata authorization: [adapters/nginx/auth_request.conf](adapters/nginx/auth_request.conf)
- NGINX njs body inspection for PHP2Shell: [adapters/nginx/php2shell-njs.md](adapters/nginx/php2shell-njs.md)
- Envoy: [adapters/envoy/ext_authz.yaml](adapters/envoy/ext_authz.yaml)

The `auth_request` example forwards metadata only and cannot inspect request
bodies. PHP2Shell body detection requires the njs access-phase integration,
which reads and caches the body before `proxy_pass` and requires njs 1.0.2 or
newer. `adapterd` exposes that route as `POST /nginx/body-check`; enable it
with `CHEESEWAF_ADAPTER_FORWARD_BODY=true`. Metadata-only routes report
`body_state: withheld` when forwarding is disabled, so the core can
distinguish an absent body from a body the gateway did not send.

The examples use a local HTTP hop for the initial contract. Production deployments should put the adapter on a private network, configure `CHEESEWAF_ADAPTER_TOKEN` (presented in the dedicated `X-CheeseWAF-Adapter-Token` header, not `Authorization`), and use mTLS before exposing it beyond the host or Pod. A non-loopback core URL must use HTTPS; environment HTTP proxies are not used for core traffic. Forwarded headers are honored only when the peer address matches `CHEESEWAF_ADAPTER_TRUSTED_PROXY_CIDRS`; for NGINX and Envoy sources the original URI, method, host, scheme and client address are required, otherwise the request fails closed.
When Envoy reports `x-envoy-auth-partial-body: true`, the adapter marks the contract body as incomplete; even an `allow`/`log` decision or a core timeout returns HTTP 413. With body forwarding disabled, a partial-body marker is rejected.

## Configuration

| Variable / flag | Default | Meaning |
| --- | --- | --- |
| `CHEESEWAF_ADAPTER_LISTEN` / `--listen` | `127.0.0.1:9080` | Adapter listener. |
| `CHEESEWAF_CORE_URL` / `--core-url` | required | Self-hosted CheeseWAF core URL. Non-loopback hosts must use `https://`; environment HTTP proxies are ignored. |
| `CHEESEWAF_CORE_INSPECT_PATH` | `/api/v1/adapter/inspect` | Inline inspection route. |
| `CHEESEWAF_CORE_TELEMETRY_PATH` | `/api/v1/adapter/telemetry` | Best-effort telemetry route. |
| `CHEESEWAF_CORE_HEALTH_PATH` | `/healthz` | Core readiness probe route; empty disables the client-side probe. Set it to `/health` if the core only exposes that route. |
| `CHEESEWAF_CORE_TOKEN` | empty | Bearer token sent from adapterd to the self-hosted core. |
| `CHEESEWAF_CORE_TLS_CA_FILE` | empty | Optional private CA bundle for the core HTTPS certificate. |
| `CHEESEWAF_CORE_TLS_CERT_FILE` / `CHEESEWAF_CORE_TLS_KEY_FILE` | empty | Optional client certificate/key pair for core mTLS. |
| `CHEESEWAF_CORE_TLS_SERVER_NAME` | empty | Optional TLS ServerName override for the core certificate. |
| `CHEESEWAF_ADAPTER_TOKEN` | empty | Optional secret required in the `X-CheeseWAF-Adapter-Token` header; set it outside loopback. It is not read from `Authorization`. |
| `CHEESEWAF_ADAPTER_TRUSTED_PROXY_CIDRS` | `127.0.0.1/32,::1/128` | CIDRs allowed to supply original/forwarded request metadata. Expand only to a controlled proxy network. |
| `CHEESEWAF_ADAPTER_REQUEST_TIMEOUT` / `--request-timeout` | `100ms` | Inline decision budget. |
| `CHEESEWAF_ADAPTER_TELEMETRY_TIMEOUT` | `500ms` | Telemetry call budget. |
| `CHEESEWAF_ADAPTER_HEALTH_TIMEOUT` | `2s` | Core readiness probe budget, independent of the inline request budget. |
| `CHEESEWAF_ADAPTER_HEALTH_CHECK` | `true` | Enables the `/readyz` core probe; `false` makes `/readyz` report disabled. |
| `CHEESEWAF_ADAPTER_FAIL_MODE` / `--fail-mode` | `closed` | `closed` returns `503`; `open` returns `204` on core failure and is logged as a fail-open event. |
| `CHEESEWAF_ADAPTER_FORWARD_BODY` | `false` | Opt in to forwarding at most the configured body limit; oversized bodies are sent with `BodyTruncated=true`, and an `allow`/`log` result returns HTTP 413. |
| `CHEESEWAF_ADAPTER_MAX_BODY_BYTES` | `65536` | Body limit when forwarding is enabled (bounded by adapter validation). |
| `CHEESEWAF_ADAPTER_FORWARD_SENSITIVE_HEADERS` | `false` | Explicitly opt in to forwarding credential-bearing headers to the self-hosted core. |

The telemetry endpoint accepts one validated JSON event at a time and is rate-limited to 100 events/second per adapter process. `contract_version` and `source` default to `v1`/`generic` when omitted; events are validated before the limiter is consumed. An empty `CHEESEWAF_CORE_TELEMETRY_PATH` makes the route return `503` instead of accepting and dropping events. Health endpoints remain probe-friendly; keep the listener private or use an adapter token/network policy.

## Contract boundary

`contracts/inspection/v1` is intentionally independent of CheeseWAF `internal` packages. It defines:

- request metadata, client context, TLS fingerprint slots, and optional response context;
- explicit `body_state` (`absent`, `withheld`, `forwarded`, `truncated`, `unsupported`) and `body_encoding`;
- `allow`, `log`, `block`, and `challenge` actions;
- policy version, rule ID, response headers, multiple `set_cookies`, and a bounded challenge body with an allowlisted content type;
- safe defaults and fail-closed validation for headers, authority, path/query, set-cookie, and body metadata.

Any new gateway adapter must use this contract or a newer versioned contract. It must not copy detector logic or import an `internal/...` package from the core repository.

## Roadmap

1. Stabilize HTTP `auth_request` and Envoy `ext_authz` conformance tests.
2. Add a streaming Envoy `ext_proc` adapter only when bounded-body and response inspection requirements justify the extra hop.
3. Add a Kubernetes sidecar controller with opt-in annotations and an explicit Service-routing mode; privileged iptables injection remains optional.
4. Add signed policy snapshots, last-known-good rollback, and asynchronous postanalytics/OOB mirror ingestion.
5. Add Kong, APISIX, and Traefik adapters after the core contract has compatibility tests.
6. Consider a separate NGINX C ABI shim only for a demonstrated native-module requirement. It must not move WAF logic out of Go.

## License

Apache-2.0. See [LICENSE](LICENSE).
