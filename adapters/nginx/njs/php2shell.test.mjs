import assert from 'node:assert/strict';
import test from 'node:test';

import { check } from './php2shell.js';

const BODY_CHECK_URL = 'http://127.0.0.1:9080/nginx/body-check';

function arrayBufferOf(text) {
    const buffer = Buffer.from(text);
    return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
}

function harness({
    method = 'POST',
    body = 'body',
    headers = {},
    variables = {},
    replyStatus = 204,
    fetch = null,
    bodyRead = null,
} = {}) {
    const calls = { returns: [], fetches: [], reads: 0 };
    const mergedHeaders = {
        'Content-Length': String(Buffer.byteLength(body)),
        'Content-Type': 'multipart/form-data; boundary=x',
    };
    Object.assign(mergedHeaders, headers);
    for (const key of Object.keys(mergedHeaders)) {
        if (mergedHeaders[key] === null) {
            delete mergedHeaders[key];
        }
    }

    const r = {
        method,
        uri: '/upload.php',
        headersIn: mergedHeaders,
        remoteAddress: '203.0.113.7',
        variables: Object.assign({
            request_uri: '/upload.php?next=%2F',
            scheme: 'https',
            request_id: 'req-1',
            cheesewaf_body_check_url: BODY_CHECK_URL,
            cheesewaf_body_check_max_bytes: '65536',
            cheesewaf_body_check_timeout_ms: '250',
        }, variables),
        readRequestArrayBuffer: async () => {
            calls.reads += 1;
            if (bodyRead) {
                return bodyRead();
            }
            return arrayBufferOf(body);
        },
        headersOut: {},
        return: (status, text) => {
            calls.returns.push({ status, text });
        },
        error: () => {},
        warn: () => {},
    };

    globalThis.ngx = {
        fetch: async (url, options) => {
            calls.fetches.push({ url, options });
            if (fetch) {
                return fetch(url, options);
            }
            return { status: replyStatus, text: async () => '' };
        },
    };

    return { r, calls };
}

function withoutAdapterToken(run) {
    const previous = process.env.CHEESEWAF_ADAPTER_TOKEN;
    delete process.env.CHEESEWAF_ADAPTER_TOKEN;
    try {
        return run();
    } finally {
        if (previous === undefined) {
            delete process.env.CHEESEWAF_ADAPTER_TOKEN;
        } else {
            process.env.CHEESEWAF_ADAPTER_TOKEN = previous;
        }
    }
}

test('GET is allowed without reading a body', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness({ method: 'GET' });
        await check(r);
        assert.equal(calls.reads, 0);
        assert.equal(calls.fetches.length, 0);
        assert.deepEqual(calls.returns, []);
    });
});

test('POST body is forwarded once and a 2xx reply grants access', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness({ method: 'PUT', body: 'payload' });
        await check(r);

        assert.equal(calls.reads, 1);
        assert.equal(calls.fetches.length, 1);
        assert.equal(calls.fetches[0].url, BODY_CHECK_URL);
        assert.equal(calls.fetches[0].options.method, 'POST');
        assert.equal(calls.fetches[0].options.body.toString(), 'payload');
        assert.equal(calls.fetches[0].options.headers['X-Original-Method'], 'PUT');
        assert.equal(calls.fetches[0].options.headers['X-Original-URI'], '/upload.php?next=%2F');
        assert.equal(calls.fetches[0].options.headers['X-Real-IP'], '203.0.113.7');
        assert.equal(calls.fetches[0].options.headers['X-Forwarded-For'], '203.0.113.7');
        assert.equal(calls.fetches[0].options.headers['X-Forwarded-Proto'], 'https');
        assert.equal(calls.fetches[0].options.headers['Content-Type'], 'multipart/form-data; boundary=x');
        assert.deepEqual(calls.returns, []);
    });
});

test('binary body bytes are forwarded unchanged', async () => {
    await withoutAdapterToken(async () => {
        const bytes = Buffer.from([0xff, 0x00, 0x80, 0x0d, 0x0a]);
        const { r, calls } = harness({
            body: '12345',
            headers: { 'Content-Length': String(bytes.length) },
            bodyRead: () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
        });
        await check(r);
        assert.deepEqual(calls.fetches[0].options.body, bytes);
    });
});

test('a 200 reply also grants access', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness({ replyStatus: 200 });
        await check(r);
        assert.deepEqual(calls.returns, []);
    });
});

test('403 from adapterd denies with 403', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness({ replyStatus: 403 });
        await check(r);
        assert.equal(calls.returns.length, 1);
        assert.equal(calls.returns[0].status, 403);
    });
});

test('413 from adapterd is preserved', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness({ replyStatus: 413 });
        await check(r);
        assert.equal(calls.returns.length, 1);
        assert.equal(calls.returns[0].status, 413);
    });
});

test('an adapter error fails closed with 503', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness({ replyStatus: 500 });
        await check(r);
        assert.equal(calls.returns.length, 1);
        assert.equal(calls.returns[0].status, 503);
    });
});

test('an unreachable adapter fails closed with 503', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness({
            fetch: async () => {
                throw new Error('connect refused');
            },
        });
        await check(r);
        assert.equal(calls.returns.length, 1);
        assert.equal(calls.returns[0].status, 503);
    });
});

test('a timeout fails closed with 503', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness({
            variables: { cheesewaf_body_check_timeout_ms: '10' },
            fetch: () => new Promise(() => {}),
        });
        await check(r);
        assert.equal(calls.returns.length, 1);
        assert.equal(calls.returns[0].status, 503);
    });
});

test('a declared body over the limit is rejected before reading', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness({
            body: '12345',
            variables: { cheesewaf_body_check_max_bytes: '4' },
        });
        await check(r);
        assert.equal(calls.reads, 0);
        assert.equal(calls.fetches.length, 0);
        assert.equal(calls.returns.length, 1);
        assert.equal(calls.returns[0].status, 413);
    });
});

test('a chunked body over the limit is rejected after reading', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness({
            body: '12345',
            headers: { 'Content-Length': null },
            variables: { cheesewaf_body_check_max_bytes: '4' },
        });
        await check(r);
        assert.equal(calls.reads, 1);
        assert.equal(calls.fetches.length, 0);
        assert.equal(calls.returns.length, 1);
        assert.equal(calls.returns[0].status, 413);
    });
});

test('an empty declared body is allowed without reading', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness({ body: '' });
        await check(r);
        assert.equal(calls.reads, 0);
        assert.equal(calls.fetches.length, 0);
        assert.deepEqual(calls.returns, []);
    });
});

test('an invalid Content-Length is rejected', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness({ headers: { 'Content-Length': 'not-a-number' } });
        await check(r);
        assert.equal(calls.reads, 0);
        assert.equal(calls.returns.length, 1);
        assert.equal(calls.returns[0].status, 400);
    });
});

test('a body read failure fails closed with 503', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness({
            bodyRead: () => {
                throw new Error('already being read');
            },
        });
        await check(r);
        assert.equal(calls.fetches.length, 0);
        assert.equal(calls.returns.length, 1);
        assert.equal(calls.returns[0].status, 503);
    });
});

test('undeclared nginx variables fall back to defaults', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness();
        r.variables = new Proxy({}, {
            get() {
                throw new Error('variable not found');
            },
        });
        await check(r);
        assert.equal(calls.fetches[0].url, BODY_CHECK_URL);
        assert.equal(calls.fetches[0].options.headers['X-Original-URI'], '/upload.php');
        assert.equal(calls.returns.length, 0);
    });
});

test('an invalid body-check URL fails closed with 503', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness({
            variables: { cheesewaf_body_check_url: 'ftp://127.0.0.1/check' },
        });
        await check(r);
        assert.equal(calls.fetches.length, 0);
        assert.equal(calls.returns.length, 1);
        assert.equal(calls.returns[0].status, 503);
    });
});

test('Authorization and Cookie are not forwarded', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness({
            headers: {
                Authorization: 'Bearer secret',
                Cookie: 'PHPSESSID=secret',
            },
        });
        await check(r);
        const headers = calls.fetches[0].options.headers;
        assert.equal(headers.Authorization, undefined);
        assert.equal(headers.Cookie, undefined);
    });
});

test('the adapter token is sent from the environment and never in the URL', async () => {
    const previous = process.env.CHEESEWAF_ADAPTER_TOKEN;
    process.env.CHEESEWAF_ADAPTER_TOKEN = 'test-token';
    try {
        const { r, calls } = harness();
        await check(r);
        assert.equal(calls.fetches[0].options.headers['X-CheeseWAF-Adapter-Token'], 'test-token');
        assert.ok(!calls.fetches[0].url.includes('test-token'));
    } finally {
        if (previous === undefined) {
            delete process.env.CHEESEWAF_ADAPTER_TOKEN;
        } else {
            process.env.CHEESEWAF_ADAPTER_TOKEN = previous;
        }
    }
});

function replyWith(status, headers = {}, body = '') {
    const values = new Map();
    for (const [key, value] of Object.entries(headers)) {
        values.set(key.toLowerCase(), Array.isArray(value) ? value.map(String) : [String(value)]);
    }
    return {
        status,
        headers: {
            get(name) {
                const found = values.get(String(name).toLowerCase());
                return found && found.length ? found[0] : null;
            },
            getAll(name) {
                return values.get(String(name).toLowerCase()) || [];
            },
        },
        text: async () => body,
    };
}

test('Content-Encoding is forwarded to the adapter', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness({
            headers: { 'Content-Encoding': 'gzip' },
        });
        await check(r);
        assert.equal(calls.fetches[0].options.headers['Content-Encoding'], 'gzip');
    });
});

test('challenge headers and body are propagated to the client', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness({
            fetch: async () => replyWith(401, {
                'WWW-Authenticate': 'Basic realm="waf"',
                'Set-Cookie': ['cw=1; Path=/; HttpOnly', 'theme=dark; Path=/'],
                Location: '/login',
                'Retry-After': '3',
                'X-CheeseWAF-Decision': 'challenge',
                'X-CheeseWAF-Request-ID': 'req-9',
            }, 'verify'),
        });
        await check(r);
        assert.equal(calls.returns.length, 1);
        assert.equal(calls.returns[0].status, 401);
        assert.equal(calls.returns[0].text, 'verify');
        assert.equal(r.headersOut['WWW-Authenticate'], 'Basic realm="waf"');
        assert.deepEqual(r.headersOut['Set-Cookie'], ['cw=1; Path=/; HttpOnly', 'theme=dark; Path=/']);
        assert.equal(r.headersOut.Location, '/login');
        assert.equal(r.headersOut['Retry-After'], '3');
        assert.equal(r.headersOut['X-CheeseWAF-Decision'], 'challenge');
        assert.equal(r.headersOut['X-CheeseWAF-Request-ID'], 'req-9');
    });
});

test('a 429 block is preserved with retry-after', async () => {
    await withoutAdapterToken(async () => {
        const { r, calls } = harness({
            fetch: async () => replyWith(429, {
                'Retry-After': '1',
                'X-CheeseWAF-Decision': 'block',
            }, ''),
        });
        await check(r);
        assert.equal(calls.returns.length, 1);
        assert.equal(calls.returns[0].status, 429);
        assert.equal(calls.returns[0].text, 'request limited\n');
        assert.equal(r.headersOut['Retry-After'], '1');
    });
});
