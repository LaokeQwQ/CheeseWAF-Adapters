# NGINX njs body inspection for PHP2Shell

`adapters/nginx/njs/php2shell.js` inspects request bodies in the NGINX access
phase and denies PHP2Shell-shaped multipart requests before `proxy_pass`. It
does not require an internal redirect, a second server block, or a change to
the upstream topology.

## Why `auth_request` is not enough

The stock `auth_request` example in
[`adapters/nginx/auth_request.conf`](auth_request.conf) sends request metadata
only:

```nginx
proxy_pass_request_body off;
proxy_set_header Content-Length "";
```

An `auth_request` subrequest therefore cannot show the body to adapterd, and
it cannot inspect the body "on the side" while the original request continues
to the upstream. The same limitation applies to a stock `auth_request`
configuration that turns body forwarding on: the authorization subrequest and
the upstream content phase compete for one client body stream, and the
metadata contract has no body field unless the adapter explicitly opts in.

`auth_request` remains useful for method, URI, header, and client-IP policy.
It MUST NOT be described as body inspection, and it does not cover PHP2Shell.

The njs integration reads the body once in `js_access`, calls adapterd, and
lets the request continue. NGINX caches the body on the request, so
`proxy_pass` forwards the original bytes to the upstream. This is the same
access-phase pattern used by the official njs
[body-signature example](https://github.com/nginx/njs-examples).

## Requirements

- **njs >= 1.0.2.** CVE-2026-18329 is fixed in 1.0.1; 1.0.1 and earlier are
  not acceptable. `js_access`, `r.return()` in the access phase, and
  `r.readRequestArrayBuffer()` are available since 0.9.9, but the security
  floor is 1.0.2.
- NGINX built with `ngx_http_js_module` (static or dynamic). QuickJS
  (`js_engine qjs`) is the supported engine for njs 1.x.
- adapterd reachable at the configured URL, with the
  `POST /nginx/body-check` route enabled by
  `CHEESEWAF_ADAPTER_FORWARD_BODY=true`; see
  [Required adapterd contract](#required-adapterd-contract).
- `client_body_buffer_size` at least as large as the inspection limit, and
  `client_max_body_size` larger than it.

## Install

1. Copy the handler next to the NGINX configuration:

   ```sh
   install -o root -g root -m 0644 \
     adapters/nginx/njs/php2shell.js /etc/nginx/njs/php2shell.js
   ```

2. Add the main-context and `http`-context lines from
   [`php2shell-njs.conf`](php2shell-njs.conf): `load_module`, `js_path`,
   `js_import`, `js_engine qjs`, and the `js_fetch_*` bounds.

3. Add the following to the protected `location`:

   ```nginx
   set $cheesewaf_body_check_url http://127.0.0.1:9080/nginx/body-check;
   set $cheesewaf_body_check_max_bytes 65536;
   set $cheesewaf_body_check_timeout_ms 2000;

   client_body_buffer_size 128k;
   client_max_body_size 1m;

   js_access php2shell.check;
   ```

   Existing `auth_request`, `allow`/`deny`, or `auth_basic` checks may stay.
   NGINX runs built-in access checkers before `js_access`.

4. If adapterd requires `CHEESEWAF_ADAPTER_TOKEN`, expose it to the worker
   environment with `env CHEESEWAF_ADAPTER_TOKEN;` in the main context. The
   handler sends it in `X-CheeseWAF-Adapter-Token` and never logs it.

   Keep the `ngx.fetch` hop on loopback, or add the NGINX source address to
   `CHEESEWAF_ADAPTER_TRUSTED_PROXY_CIDRS` on adapterd. Without that trust,
   adapterd ignores `X-Original-Method` and `X-Original-URI` and sees only
   `POST /nginx/body-check`. For a cross-host hop, use an HTTPS adapter URL
   and configure `js_fetch_trusted_certificate` for the private CA.

5. Test and reload:

   ```sh
   nginx -t
   nginx -s reload
   ```

The inspection limit defaults to 65536 bytes to match adapterd's
`CHEESEWAF_ADAPTER_MAX_BODY_BYTES` default. The handler also caps the
configured value at 1 MiB. Keep the NGINX values and adapterd's configured
limit aligned; otherwise a body can pass NGINX and be rejected by adapterd.
POST/PUT/PATCH bodies above the limit receive `413`, including otherwise
legitimate large uploads. Raise `$cheesewaf_body_check_max_bytes` and
`client_max_body_size` together when the protected site accepts them.
Allowing oversized bodies through uninspected would create a padding bypass.

## Capability check

Run these on the NGINX host before enabling `js_access`:

```sh
# The module is present, either statically or as a loadable object.
nginx -V 2>&1 | tr ' ' '\n' | grep -E 'with-http_js_module|ngx_http_js_module'

# Exact njs version. Require 1.0.2 or newer.
njs -v

# If the njs CLI is not packaged separately, query the distribution package.
dpkg-query -W -f='${Version}\n' libnginx-mod-http-js 2>/dev/null
rpm -q nginx-module-njs 2>/dev/null
```

Check adapterd separately. A 404 or 405 means the route is missing, not that
the request was allowed:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' \
  -X POST \
  -H 'Content-Type: multipart/form-data; boundary=x' \
  -H 'X-Original-Method: POST' \
  -H 'X-Original-URI: /upload.php' \
  -H 'X-Forwarded-Host: example.test' \
  -H 'X-Forwarded-Proto: https' \
  -H 'X-Real-IP: 203.0.113.10' \
  --data-binary $'--x\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\nx\r\n--x--\r\n' \
  http://127.0.0.1:9080/nginx/body-check
```

Expected status: `204` (allow), `401` (challenge or bad adapter token),
`403` (deny), `413` (body too large), or `429` (rate limited).
`404`/`405` means the adapterd route is not installed. `503` means
inspection is unavailable.

Enable the handler only after that probe returns a decision status. The
handler fails closed when adapterd is missing or unreachable. It does **not**
override adapterd's `CHEESEWAF_ADAPTER_FAIL_MODE`; if that is set to `open`,
a core outage allows the request. Keep `closed` for body inspection.

## Required adapterd contract

The handler expects these semantics, matching the existing adapter decision
mapping:

| Item | Value |
| --- | --- |
| Method and path | `POST /nginx/body-check` |
| Body | Raw request bytes, at most the configured inspection limit |
| `Content-Type` | Original client value, including the multipart boundary |
| `Content-Encoding` | Original client value when present |
| Metadata headers | `X-Original-Method`, `X-Original-URI`, `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Request-ID` |
| Optional auth | `X-CheeseWAF-Adapter-Token` |
| Allow | Any `2xx` |
| Deny | Any `4xx` (normally `403`) |
| Challenge | `401`, with `WWW-Authenticate`, `Set-Cookie`, and optional body |
| Body too large | `413` |
| Rate limited | `429`, with `Retry-After` |
| Error/timeout | Any other status, or no response |

The route is implemented in `internal/adapter/httpserver/server.go`. It
requires `POST`, `CHEESEWAF_ADAPTER_FORWARD_BODY=true`, and a non-empty
request body. It builds an inspection request with `body_state=forwarded` or
`body_state=truncated` and the original method/URI metadata. When the body
exceeds the adapter limit, the prefix is still sent to the core marked
truncated; an `allow`/`log` result becomes `413`, never an implicit allow.
The body is forwarded only to the self-hosted core and is never logged.

## Privacy and limits

- Up to the configured limit (default 64 KiB) of each POST/PUT/PATCH body is
  copied to adapterd. Bodies are not written to the NGINX error log.
- Only the headers listed above are sent. `Authorization`, `Cookie`, and
  client-supplied `X-Forwarded-For` chains are not forwarded.
- The original URI, including its query string, is sent as metadata. Do not
  put credentials in query strings.
- The body is held in memory by the access handler; `client_body_buffer_size`
  must cover the inspection limit. The example uses 128 KiB, so raise it to
  at least the configured limit if you increase the limit above 128 KiB. Do
  not disable request buffering.
- `$cheesewaf_body_check_timeout_ms` is one deadline covering both the body
  read and the adapter call, not a separate budget for each. The 2s default
  is ample for 64 KiB on normal links; raise it for slow clients or larger
  limits.
- The PHP2Shell detector is multipart-specific. The handler still forwards
  bounded non-multipart bodies when POST/PUT/PATCH is used; the core decides
  whether they are relevant.

## Handler tests

The handler tests use Node's built-in test runner and a fake request object;
they do not require Docker or NGINX:

```sh
node --test adapters/nginx/njs/php2shell.test.mjs
```

The tests cover method gating, bounded bodies, deny/allow mapping, timeouts,
adapter failures, header minimization, and token handling. They do not
exercise NGINX's body cache or `proxy_pass`; verify that path on a staging
NGINX with the capability check above.

## Rollback

1. Comment out `js_access php2shell.check;` in the protected location.
2. Run `nginx -t` and `nginx -s reload`.

This stops body inspection immediately; upstream traffic and the existing
`auth_request` metadata checks are unaffected. No request state survives a
reload. If you also remove `load_module`, `js_import`, or `js_engine`, the
change requires a full NGINX restart rather than a reload.

If adapterd is unavailable and you need to restore traffic, remove
`js_access` rather than pointing the handler at a permissive stub. The
handler's `503` is intentional fail-closed behavior.
