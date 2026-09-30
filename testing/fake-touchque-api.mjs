#!/usr/bin/env node
// Shared fake TouchQue API for SDK contract tests (Python, PHP, Go).
// No dependencies. Verifies request signatures exactly like the real API
// (HMAC-SHA256 over METHOD:path[?query]:timestamp:nonce:sha256(body)), so
// every SDK's signing is tested too.
//
//   node testing/fake-touchque-api.mjs   → prints {"port":NNNN} on stdout
//   API key: tq_test_key   API secret: test_secret
//
// Test control (unsigned): POST /__test/link {user}, /__test/approve {id?, via?},
// /__test/reject {id?}, /__test/opts {...}, /__test/reset; GET /__test/calls

import http from 'node:http';
import crypto from 'node:crypto';

const API_KEY = 'tq_test_key';
const API_SECRET = 'test_secret';

let state;
function reset() {
  state = {
    requests: [], linked: new Set(), pending: new Set(), calls: [], opts: {}, seq: 0,
    actions: new Map([['LOGIN', { critical: false }], ['SEND_MONEY', { critical: true }]]),
    challenges: new Map(), usedNonces: new Set(),
  };
}
reset();

const toPairs = (d) => (!d ? null : Array.isArray(d) ? d.map((x) => ({ label: String(x.label), value: String(x.value) }))
  : Object.entries(d).map(([label, value]) => ({ label, value: String(value) })));
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function verifySignature(req, rawBody) {
  const key = req.headers['x-api-key'];
  const sig = req.headers['x-signature'];
  const ts = req.headers['x-timestamp'];
  const nonce = req.headers['x-nonce'];
  if (key !== API_KEY) return 'bad_key';
  if (!sig || !ts || !nonce) return 'missing_headers';
  if (String(nonce).length < 16) return 'short_nonce';
  if (state.usedNonces.has(nonce)) return 'nonce_reused';
  const tsMs = /^\d+$/.test(ts) ? Number(ts) : Date.parse(ts);
  if (!Number.isFinite(tsMs) || Math.abs(Date.now() - tsMs) > 5 * 60 * 1000) return 'bad_timestamp';
  const [path, query] = req.url.split('?');
  const candidates = query ? [`${path}?${query}`, path] : [path];
  const ok = candidates.some((p) => {
    const expected = crypto.createHmac('sha256', API_SECRET).update(`${req.method}:${p}:${ts}:${nonce}:${sha256(rawBody)}`).digest('hex');
    return expected.length === String(sig).length && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(String(sig)));
  });
  if (!ok) return 'bad_signature';
  state.usedNonces.add(nonce);
  return null;
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

const routes = [];
const route = (method, pattern, fn) => routes.push({ method, re: new RegExp(`^${pattern}$`), fn });
const pick = (id) => (id ? state.requests.find((r) => r.id === id) : state.requests[state.requests.length - 1]);

// ── test control ──
route('POST', '/__test/reset', (req, res) => { reset(); send(res, 200, { ok: true }); });
route('POST', '/__test/link', (req, res, b) => { state.linked.add(b.user); send(res, 200, { ok: true }); });
route('POST', '/__test/opts', (req, res, b) => { state.opts = { ...state.opts, ...b }; send(res, 200, state.opts); });
route('POST', '/__test/approve', (req, res, b) => { const r = pick(b.id); r.status = 'CONFIRMED'; r.confirmedVia = b.via || 'DEVICE'; send(res, 200, { id: r.id }); });
route('POST', '/__test/reject', (req, res, b) => { const r = pick(b.id); r.status = 'REJECTED'; send(res, 200, { id: r.id }); });
route('GET', '/__test/calls', (req, res) => send(res, 200, state.calls));

// ── API ──
route('POST', '/login/request', (req, res, b) => {
  const { externalUsername: user, type, referenceId = null, details } = b;
  if (!state.linked.has(user)) return send(res, 404, { code: 'device_not_linked', error: 'No linked device found for this user' });
  if (state.opts.frozen) return send(res, 423, { code: 'frozen', error: 'frozen', retryAfter: 900 }, { 'Retry-After': '900' });
  if (state.opts.rateLimited) return send(res, 429, { code: 'rate_limited', error: 'too_many_login_requests', retryAfter: 60 }, { 'Retry-After': '60' });
  const action = state.actions.get(type);
  if (!action) return send(res, 400, { code: 'unknown_action', error: `Invalid action type: ${type}` });
  if (state.opts.blocked) return send(res, 403, { code: 'blocked', reason: state.opts.blocked, error: 'blocked' });
  const r = {
    id: `00000000-0000-4000-8000-${String(++state.seq).padStart(12, '0')}`, user, type, referenceId, details: toPairs(details),
    status: 'PENDING', consumed: false,
    challengeCode: state.opts.passkeyOnly ? undefined : (state.opts.numberMatch || action.critical ? '47' : undefined),
    requiresPasskey: state.opts.passkeyOnly || undefined,
  };
  state.requests.push(r);
  send(res, 200, { message: 'Request sent', requestId: r.id, challengeCode: r.challengeCode, expiresAt: new Date(Date.now() + 30000).toISOString(), requiresPasskey: r.requiresPasskey });
});
const assurance = (r) => ({ phishingResistant: r.confirmedVia === 'WEBAUTHN', method: r.confirmedVia === 'WEBAUTHN' ? 'passkey' : 'push' });
route('GET', '/login/status/([^/]+)', (req, res, b, m) => {
  const r = pick(decodeURIComponent(m[1]));
  if (!r || r.id !== decodeURIComponent(m[1])) return send(res, 404, { code: 'not_found' });
  send(res, 200, {
    status: r.status, externalUsername: r.user, type: r.type, referenceId: r.referenceId, details: r.details, consumed: r.consumed,
    requiresPasskey: r.requiresPasskey, confirmedVia: r.confirmedVia || null, assurance: r.status === 'CONFIRMED' ? assurance(r) : null,
  });
});
route('POST', '/login/([^/]+)/consume', (req, res, b, m) => {
  const r = state.requests.find((x) => x.id === m[1]);
  if (!r) return send(res, 404, { code: 'not_found' });
  if (r.status !== 'CONFIRMED') return send(res, 409, { code: r.status === 'REJECTED' ? 'rejected' : r.status === 'EXPIRED' ? 'expired' : 'not_approved' });
  if (r.consumed) return send(res, 409, { code: 'already_used' });
  r.consumed = true;
  send(res, 200, {
    consumed: true, requestId: r.id, externalUsername: r.user, type: r.type, referenceId: r.referenceId, details: r.details,
    confirmedVia: r.confirmedVia, assurance: assurance(r), approvalProof: null,
  });
});
route('POST', '/login/recovery', (req, res, b) => send(res, 200, { success: true }));
route('POST', '/auth/generate-secret', (req, res, b) => {
  const u = b.externalUsername;
  if (state.linked.has(u)) return send(res, 409, { error: 'already linked' });
  if (state.pending.has(u)) return send(res, 409, { error: 'Secret already generated' });
  state.pending.add(u);
  send(res, 200, { secret: 'S', qrCodeDataUrl: `data:image/png;base64,QR-${u}`, externalUsername: u, expiresAt: 'soon', ttlMs: 300000, recoveryCodes: ['r1'] });
});
route('POST', '/auth/secret/reset', (req, res, b) => {
  const u = b.externalUsername;
  state.linked.delete(u);
  state.pending.add(u);
  send(res, 200, { success: true, secret: 'S2', qrCodeDataUrl: `data:image/png;base64,QR2-${u}`, externalUsername: u, recoveryCodes: ['r2'] });
});
route('GET', '/users/([^/]+)', (req, res, b, m) => {
  const u = decodeURIComponent(m[1]);
  if (!state.linked.has(u) && !state.pending.has(u)) return send(res, 404, { error: 'not found' });
  send(res, 200, { externalUsername: u, deviceId: state.linked.has(u) ? 'dev-1' : null, used: state.linked.has(u), frozen: false });
});
route('POST', '/action-types', (req, res, b) => {
  state.actions.set(b.type, { critical: !!b.critical });
  send(res, 200, { id: 'a1', type: b.type, name: b.name, description: b.description || '', critical: !!b.critical, active: true });
});
route('GET', '/action-types', (req, res) => send(res, 200, [...state.actions.entries()].map(([type, a]) => ({ type, ...a }))));
// Like the real API: a QR that follows a push is tied to it. A request the phone REJECTED kills the QR
// (none is issued, a code is refused), and a push with number matching makes the QR show the same number.
route('POST', '/offline/challenge', (req, res, b) => {
  if (state.opts.offlineDisabled) return send(res, 403, { error: 'offline_sign_disabled', code: 'offline_sign_disabled' });
  const linked = b.requestId ? state.requests.find((x) => x.id === b.requestId) : undefined;
  if (b.requestId && !linked) return send(res, 404, { error: 'request_not_found' });
  if (linked && linked.status === 'REJECTED') return send(res, 409, { error: 'request_rejected' });
  const id = `ch-${++state.seq}`;
  state.challenges.set(id, { user: b.externalUsername, type: b.type, used: false, requestId: linked && linked.id });
  const challengeCode = (linked && linked.challengeCode) || (b.requireNumberMatch === true ? '47' : undefined);
  send(res, 200, { challengeId: id, qr: 'TQ2.x', qrDataUrl: 'data:image/png;base64,OFFLINE', expiresAt: 'soon', expiresInSeconds: 120, totpAvailable: true, ...(challengeCode ? { challengeCode } : {}) });
});
route('POST', '/offline/verify', (req, res, b) => {
  const ch = state.challenges.get(b.challengeId);
  if (!ch) return send(res, 404, { approved: false, reason: 'unknown_challenge' });
  if (ch.used) return send(res, 410, { approved: false, reason: 'used' });
  if (ch.requestId && (state.requests.find((x) => x.id === ch.requestId) || {}).status === 'REJECTED') return send(res, 410, { approved: false, reason: 'request_rejected' });
  if (b.code !== 'ABCD123') return send(res, 401, { approved: false, reason: 'invalid_code', attemptsLeft: 4 });
  ch.used = true;
  send(res, 200, { approved: true, challengeId: b.challengeId, externalUsername: ch.user, type: ch.type });
});
route('POST', '/offline/totp/verify', (req, res, b) => {
  if (b.requestId && (state.requests.find((x) => x.id === b.requestId) || {}).status === 'REJECTED') return send(res, 410, { approved: false, reason: 'request_rejected' });
  if (b.code !== '123456') return send(res, 401, { approved: false, reason: 'invalid_code' });
  send(res, 200, { approved: true, externalUsername: b.externalUsername });
});
route('GET', '/webauthn/credentials', (req, res) => send(res, 200, { credentials: [] }));
route('DELETE', '/webauthn/credentials/([^/]+)', (req, res) => send(res, 200, { deleted: true }));

const server = http.createServer((req, res) => {
  let raw = '';
  req.on('data', (c) => { raw += c; });
  req.on('end', () => {
    const [path] = req.url.split('?');
    const r = routes.find((x) => x.method === req.method && x.re.test(path));
    if (!r) return send(res, 404, { error: 'no route' });
    let body = {};
    try { body = raw ? JSON.parse(raw) : {}; } catch { return send(res, 400, { error: 'bad json' }); }
    if (!path.startsWith('/__test/')) {
      const bad = verifySignature(req, raw);
      if (bad) return send(res, 401, { code: bad, error: bad });
      state.calls.push({ method: req.method, path, url: req.url, body });
    }
    try { r.fn(req, res, body, path.match(r.re)); } catch (e) { send(res, 500, { error: String(e) }); }
  });
});
server.listen(Number(process.env.PORT || 0), '127.0.0.1', () => {
  process.stdout.write(`${JSON.stringify({ port: server.address().port })}\n`);
});
process.on('SIGTERM', () => server.close(() => process.exit(0)));
