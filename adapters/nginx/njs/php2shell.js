// Body inspection for the PHP2Shell multipart bug (CVE-2026-109618/109619).
//
// This runs in the NGINX access phase for POST, PUT, and PATCH requests.
// It reads and caches the client body, forwards at most BODY_LIMIT bytes to
// adapterd's /nginx/body-check route, and leaves the cached body for
// proxy_pass. A 2xx reply grants access without calling r.return(), so the
// upstream receives the original body unchanged.
//
// Requires njs >= 1.0.2. js_access and the r.readRequest*() readers exist
// since njs 0.9.9, but 1.0.1 fixes CVE-2026-18329 and earlier releases must
// not be used.

const INSPECTED_METHODS = ['POST', 'PUT', 'PATCH'];
const DEFAULT_BODY_LIMIT_BYTES = 64 * 1024;
const HARD_BODY_LIMIT_BYTES = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 2000;
const MAX_TIMEOUT_MS = 10000;
const DEFAULT_BODY_CHECK_URL = 'http://127.0.0.1:9080/nginx/body-check';

function boundedInt(value, fallback, maximum) {
    if (value === undefined || value === null || value === '') {
        return fallback;
    }
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed <= 0) {
        return fallback;
    }
    return Math.min(Math.floor(parsed), maximum);
}

function parseContentLength(value) {
    if (value === undefined || value === null) {
        return null;
    }
    const raw = String(value).trim();
    if (raw === '') {
        return null;
    }
    if (!/^[0-9]+$/.test(raw)) {
        return NaN;
    }
    const parsed = Number(raw);
    return Number.isSafeInteger(parsed) ? parsed : NaN;
}

function bodyBytes(body) {
    if (body === undefined || body === null) {
        return 0;
    }
    if (typeof body.byteLength === 'number') {
        return body.byteLength;
    }
    if (typeof body.length === 'number') {
        return body.length;
    }
    return NaN;
}

function optionalVariable(r, name, fallback) {
    try {
        const value = r.variables[name];
        if (value === undefined || value === null || value === '') {
            return fallback;
        }
        return value;
    } catch (err) {
        // njs throws for variables that are not declared in nginx.conf.
        return fallback;
    }
}

function adapterToken() {
    if (typeof process === 'undefined' || !process.env) {
        return '';
    }
    return process.env.CHEESEWAF_ADAPTER_TOKEN || '';
}

function buildHeaders(r, method) {
    const headers = {
        'Content-Type': r.headersIn['Content-Type'] || 'application/octet-stream',
        'X-Original-Method': method,
    };

    const encoding = r.headersIn['Content-Encoding'];
    if (encoding) {
        headers['Content-Encoding'] = String(encoding).trim();
    }

    const uri = optionalVariable(r, 'request_uri', r.uri);
    if (uri) {
        headers['X-Original-URI'] = uri;
    }
    if (r.headersIn.host) {
        headers['X-Forwarded-Host'] = r.headersIn.host;
    }
    const scheme = optionalVariable(r, 'scheme', '');
    if (scheme) {
        headers['X-Forwarded-Proto'] = scheme;
    }
    if (r.remoteAddress) {
        // Overwrite, rather than append, any client-supplied forwarding chain.
        headers['X-Real-IP'] = r.remoteAddress;
        headers['X-Forwarded-For'] = r.remoteAddress;
    }
    const requestId = optionalVariable(r, 'request_id', '');
    if (requestId) {
        headers['X-Request-ID'] = requestId;
    }

    const token = adapterToken();
    if (token) {
        headers['X-CheeseWAF-Adapter-Token'] = token;
    }
    return headers;
}

async function withTimeout(promise, timeoutMs, operation) {
    let timer = null;
    const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(operation + ' timed out')), timeoutMs);
    });
    try {
        return await Promise.race([promise, timeout]);
    } finally {
        clearTimeout(timer);
    }
}

function denyUnavailable(r, message) {
    r.error('cheesewaf php2shell: ' + message);
    r.return(503, 'request body inspection unavailable\n');
}

function responseHeader(reply, name) {
    try {
        if (!reply || !reply.headers || typeof reply.headers.get !== 'function') {
            return '';
        }
        const value = reply.headers.get(name);
        return value === undefined || value === null ? '' : String(value);
    } catch (err) {
        return '';
    }
}

function responseHeaders(reply, name) {
    try {
        if (!reply || !reply.headers || typeof reply.headers.getAll !== 'function') {
            return [];
        }
        const values = reply.headers.getAll(name);
        if (Array.isArray(values)) {
            return values.map(String).filter(Boolean);
        }
        return values === undefined || values === null ? [] : [String(values)];
    } catch (err) {
        return [];
    }
}

function applyDecisionHeaders(r, reply) {
    const single = {
        'WWW-Authenticate': responseHeader(reply, 'www-authenticate'),
        Location: responseHeader(reply, 'location'),
        'Retry-After': responseHeader(reply, 'retry-after'),
        'X-CheeseWAF-Decision': responseHeader(reply, 'x-cheesewaf-decision'),
        'X-CheeseWAF-Request-ID': responseHeader(reply, 'x-cheesewaf-request-id'),
    };
    for (const [name, value] of Object.entries(single)) {
        if (value) {
            r.headersOut[name] = value;
        }
    }
    const cookies = responseHeaders(reply, 'set-cookie');
    if (cookies.length) {
        r.headersOut['Set-Cookie'] = cookies;
    }
}

async function decisionBody(reply) {
    try {
        if (!reply || typeof reply.text !== 'function') {
            return '';
        }
        return await reply.text();
    } catch (err) {
        return '';
    }
}

function defaultDecisionBody(status) {
    if (status === 413) {
        return 'request body exceeds inspection limit\n';
    }
    if (status === 429) {
        return 'request limited\n';
    }
    return 'request blocked\n';
}

async function check(r) {
    const method = String(r.method || '').toUpperCase();
    if (INSPECTED_METHODS.indexOf(method) === -1) {
        return;
    }

    const limit = boundedInt(
        optionalVariable(r, 'cheesewaf_body_check_max_bytes', ''),
        DEFAULT_BODY_LIMIT_BYTES,
        HARD_BODY_LIMIT_BYTES
    );
    const timeoutMs = boundedInt(
        optionalVariable(r, 'cheesewaf_body_check_timeout_ms', ''),
        DEFAULT_TIMEOUT_MS,
        MAX_TIMEOUT_MS
    );
    const deadline = Date.now() + timeoutMs;
    const remaining = () => Math.max(1, deadline - Date.now());

    const declared = parseContentLength(r.headersIn['Content-Length']);
    if (Number.isNaN(declared)) {
        r.return(400, 'invalid Content-Length\n');
        return;
    }
    if (declared === 0) {
        return;
    }
    if (declared !== null && declared > limit) {
        r.return(413, 'request body exceeds inspection limit\n');
        return;
    }

    let raw;
    try {
        raw = await withTimeout(r.readRequestArrayBuffer(), remaining(), 'request body read');
    } catch (err) {
        denyUnavailable(r, 'request body read failed: ' + (err && err.message ? err.message : err));
        return;
    }

    if (raw === undefined || raw === null) {
        denyUnavailable(r, 'request body reader returned no data');
        return;
    }
    const length = bodyBytes(raw);
    if (!Number.isFinite(length)) {
        denyUnavailable(r, 'request body length is unknown');
        return;
    }
    if (length === 0) {
        return;
    }
    if (length > limit) {
        r.return(413, 'request body exceeds inspection limit\n');
        return;
    }

    const url = String(
        optionalVariable(r, 'cheesewaf_body_check_url', DEFAULT_BODY_CHECK_URL)
    ).trim();
    if (!/^https?:\/\//.test(url)) {
        denyUnavailable(r, 'invalid body-check URL');
        return;
    }

    let reply;
    try {
        reply = await withTimeout(
            ngx.fetch(url, {
                method: 'POST',
                headers: buildHeaders(r, method),
                body: Buffer.from(raw),
                max_response_body_size: 4096,
            }),
            remaining(),
            'body-check request'
        );
    } catch (err) {
        denyUnavailable(r, 'body-check request failed: ' + (err && err.message ? err.message : err));
        return;
    }

    const status = Number(reply.status);
    if (!Number.isFinite(status)) {
        denyUnavailable(r, 'body-check returned an invalid status');
        return;
    }
    if (status >= 200 && status < 300) {
        applyDecisionHeaders(r, reply);
        return;
    }
    if (status >= 400 && status < 500) {
        applyDecisionHeaders(r, reply);
        const body = await decisionBody(reply);
        r.return(status, body || defaultDecisionBody(status));
        return;
    }
    denyUnavailable(r, 'body-check returned status ' + status);
}

export default { check };
export { check };
