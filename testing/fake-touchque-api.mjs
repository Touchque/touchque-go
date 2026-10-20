#!/usr/bin/env node
// Shared fake TouchQue API for SDK contract tests (Python, PHP, Go).
// No dependencies. Verifies request signatures exactly like the real API
// (HMAC-SHA256 over METHOD:path[?query]:timestamp:nonce:sha256(body)), so
// every SDK's signing is tested too.
//
//   node testing/fake-touchque-api.mjs   → prints {"port":NNNN} on stdout
//   API key: tq_test_key   API secret: test_secret
//
// Test control (unsigned): POST /__test/link {user}, /__test/approve {id?, via?, provisional?},
// /__test/reject {id?}, /__test/escalate {id?} (Vishing Shield: the phone tap
// moved the request to a passkey), /__test/reconfirm {id?}, /__test/revoke
// {id?, reason?}, /__test/opts {...} (canary: true adds `canary` to new
// requests; silent: true makes POST /risk/check answer prompt:false for an
// everyday action), /__test/reset; GET /__test/calls, GET /__test/last-check
// (the body of the last POST /risk/check, or null)
//
// Silent sign-ins: POST /login/request remembers `browserProof`; approving
// such a request (not provisional) makes that browser known to
// GET /risk/browsers until POST /risk/browsers/forget.
//
// Never Locked Out: /recovery/* keeps vouchers and cases in memory. A linked
// user can vouch. POST /__test/recovery {id?, to} moves a case to VOUCHING
// (the new phone bound, codes 11, 12, ...), COOLING or COMPLETED.
//
// TouchQue Actions: /actions* keeps Actions, versions and secret names in
// memory (no code runs: test and dry-run answer empty results). A version that
// asks for a capability is pending_approval until POST /__test/approve-version
// {slug, number} (the dashboard's phone approval).
import http from 'node:http';
import crypto from 'node:crypto';

const API_KEY = 'tq_test_key';
const API_SECRET = 'test_secret';

let state;
function reset() {
  state = {
    requests: [], linked: new Set(), pending: new Set(), calls: [], opts: {}, seq: 0,
    actions: new Map([['LOGIN', { critical: false }], ['SEND_MONEY', { critical: true }], ['PASSKEY_ENROLL', { critical: true }]]),
    usedEnrollApprovals: new Set(),
    challenges: new Map(), usedNonces: new Set(),
    browsers: [], lastCheck: null,
    vouchers: new Map(), recoveries: [],
    flows: new Map(), secrets: new Map(),
  };
}
reset();

const toPairs = (d) => (!d ? null : Array.isArray(d) ? d.map((x) => ({ label: String(x.label), value: String(x.value) }))
  : Object.entries(d).map(([label, value]) => ({ label, value: String(value) })));
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const b64u = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// RFC 7638 thumbprint of the proof's key, like the API (object or base64url JSON
// string). The fake does not check the signature; an unreadable proof gets a
// stable stand-in so tests can still tell browsers apart.
function browserThumbprint(proof) {
  try {
    const p = typeof proof === 'string' ? JSON.parse(Buffer.from(proof, 'base64url').toString('utf8')) : proof;
    const { crv, kty, x, y } = p.jwk;
    if (typeof x !== 'string' || typeof y !== 'string') throw new Error('no key');
    return b64u(crypto.createHash('sha256').update(JSON.stringify({ crv, kty, x, y })).digest());
  } catch {
    return b64u(crypto.createHash('sha256').update(typeof proof === 'string' ? proof : JSON.stringify(proof)).digest());
  }
}
// The engine's English texts for the reason codes the fake answers with.
const REASON_TEXT = {
  known_browser: 'This browser proved its device-bound key',
  recent_approval: 'Approved on the phone in this browser 3 h ago',
  same_phone: 'The same phone approved this browser',
  familiar_network: 'Country and network seen in earlier approved sign-ins',
  no_risk_signal: 'No risk signal',
  no_browser_key: 'No device-bound browser key was presented',
  new_browser: 'This browser has not been approved on the phone for this account',
  critical_action: 'The action is critical',
  passkey_required: 'The workspace requires a passkey for this action',
  number_match_requested: 'The risk check asked for number matching',
  phone_not_linked: 'No phone is linked to this account',
};
const reasons = (...codes) => codes.map((code) => ({ code, text: REASON_TEXT[code] }));
// Like the API: only a real second factor makes a browser known (a confirmed push that is not provisional, a passkey).
function rememberBrowser(r) {
  if (!r.browserProof || r.status !== 'CONFIRMED' || r.provisional) return;
  const thumbprint = browserThumbprint(r.browserProof);
  const now = new Date().toISOString();
  const lastMfaMethod = r.confirmedVia === 'WEBAUTHN' ? 'passkey' : 'push';
  const known = state.browsers.find((x) => x.user === r.user && x.thumbprint === thumbprint);
  if (known) Object.assign(known, { lastMfaAt: now, lastMfaMethod, lastSeenAt: now });
  else state.browsers.push({ user: r.user, thumbprint, label: 'Browser', createdAt: now, lastMfaAt: now, lastMfaMethod, lastSeenAt: now, lastSilentAt: null });
}

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
route('POST', '/__test/approve', (req, res, b) => {
  const r = pick(b.id); r.status = 'CONFIRMED'; r.confirmedVia = b.via || 'DEVICE'; r.provisional = Boolean(b.provisional);
  rememberBrowser(r);
  send(res, 200, { id: r.id });
});
// Like the API's Vishing Shield: still PENDING, now passkey-only, the phone was refused.
route('POST', '/__test/escalate', (req, res, b) => { const r = pick(b.id); r.requiresPasskey = true; r.challengeCode = undefined; send(res, 200, { id: r.id }); });
route('POST', '/__test/reconfirm', (req, res, b) => { const r = pick(b.id); r.reconfirmedAt = new Date().toISOString(); send(res, 200, { id: r.id }); });
route('POST', '/__test/revoke', (req, res, b) => { const r = pick(b.id); r.revokedAt = new Date().toISOString(); r.revokeReason = b.reason || 'COACHED'; send(res, 200, { id: r.id }); });
route('POST', '/__test/reject', (req, res, b) => { const r = pick(b.id); r.status = 'REJECTED'; send(res, 200, { id: r.id }); });
route('GET', '/__test/calls', (req, res) => send(res, 200, state.calls));
route('POST', '/__test/recovery', (req, res, b) => {
  const c = b.id ? state.recoveries.find((x) => x.recoveryId === b.id) : state.recoveries[state.recoveries.length - 1];
  if (!c) return send(res, 404, { error: 'no recovery' });
  c.status = b.to;
  if (b.to === 'VOUCHING') { c.newPhoneBound = true; c.vouchers.forEach((v, i) => Object.assign(v, { state: 'pending', code: String(11 + i) })); }
  if (b.to === 'COOLING') { c.vouchers.forEach((v) => Object.assign(v, { state: 'approved', code: null })); c.approvals = c.vouchers.length; c.coolOffUntil = new Date(Date.now() + 3600000).toISOString(); }
  if (b.to === 'COMPLETED') { c.method = 'vouch'; c.completedAt = new Date().toISOString(); c.endedReason = 'cooling_off_ended'; }
  send(res, 200, { id: c.recoveryId, status: c.status });
});
route('POST', '/__test/approve-version', (req, res, b) => {
  const a = state.flows.get(b.slug);
  const v = a && a.versions.find((x) => x.number === b.number);
  if (!v) return send(res, 404, { error: 'no such version' });
  Object.assign(v, { status: 'ready', approvedCapabilities: v.capabilities, approvedAt: new Date().toISOString() });
  a.activeVersion = v.number;
  send(res, 200, { ok: true });
});
route('GET', '/__test/last-check', (req, res) => send(res, 200, state.lastCheck));

// ── API ──
route('POST', '/login/request', (req, res, b) => {
  const { externalUsername: user, type, referenceId = null, details } = b;
  if (!state.linked.has(user)) return send(res, 404, { code: 'device_not_linked', error: 'No linked device found for this user' });
  // "Why?": every decision names a case code (refusals: REF-USE, pushes: K7P-2QX, checks: CHK-2QX).
  if (state.opts.frozen) return send(res, 423, { code: 'frozen', error: 'frozen', retryAfter: 900, caseCode: 'REF-USE' }, { 'Retry-After': '900' });
  if (state.opts.rateLimited) return send(res, 429, { code: 'rate_limited', error: 'too_many_login_requests', retryAfter: 60, caseCode: 'REF-USE' }, { 'Retry-After': '60' });
  const action = state.actions.get(type);
  if (!action) return send(res, 400, { code: 'unknown_action', error: `Invalid action type: ${type}` });
  if (state.opts.blocked) return send(res, 403, { code: 'blocked', reason: state.opts.blocked, error: 'blocked', caseCode: 'REF-USE' });
  // Like the API: an approval given during a call and not re-confirmed yet pauses critical actions.
  if (action.critical && state.requests.some((x) => x.user === user && x.status === 'CONFIRMED' && x.provisional && !x.reconfirmedAt && !x.revokedAt)) {
    return send(res, 403, { code: 'blocked', reason: 'provisional', error: 'blocked', caseCode: 'REF-USE' });
  }
  const r = {
    id: `00000000-0000-4000-8000-${String(++state.seq).padStart(12, '0')}`, user, type, referenceId, details: toPairs(details),
    status: 'PENDING', consumed: false,
    challengeCode: state.opts.passkeyOnly ? undefined : (state.opts.numberMatch || action.critical ? '47' : undefined),
    requiresPasskey: state.opts.passkeyOnly || undefined,
    browserProof: b.browserProof || undefined,
  };
  state.requests.push(r);
  const why = [...(r.requiresPasskey ? ['passkey_required'] : []), ...(action.critical ? ['critical_action'] : []), ...(state.opts.numberMatch ? ['number_match_requested'] : [])];
  send(res, 200, {
    message: 'Request sent', requestId: r.id, challengeCode: r.challengeCode, expiresAt: new Date(Date.now() + 30000).toISOString(), requiresPasskey: r.requiresPasskey,
    caseCode: 'K7P-2QX', ...(why.length && { reasons: reasons(...why) }),
    ...(state.opts.telemetry && { telemetryToken: 'tt_test' }),
    ...(state.opts.canary && { canary: { url: `http://127.0.0.1:${server.address().port}/c/canary-${r.id}.gif` } }),
  });
});
const shieldFields = (r) => ({
  provisional: Boolean(r.provisional), reconfirmedAt: r.reconfirmedAt || null, revoked: Boolean(r.revokedAt), revokeReason: r.revokeReason || null,
});
const assurance = (r) => ({ phishingResistant: r.confirmedVia === 'WEBAUTHN', method: r.confirmedVia === 'WEBAUTHN' ? 'passkey' : 'push' });
route('GET', '/login/status/([^/]+)', (req, res, b, m) => {
  const r = pick(decodeURIComponent(m[1]));
  if (!r || r.id !== decodeURIComponent(m[1])) return send(res, 404, { code: 'not_found' });
  send(res, 200, {
    status: r.status, externalUsername: r.user, type: r.type, referenceId: r.referenceId, details: r.details, consumed: r.consumed,
    requiresPasskey: r.requiresPasskey, confirmedVia: r.confirmedVia || null, assurance: r.status === 'CONFIRMED' ? assurance(r) : null,
    ...shieldFields(r),
  });
});
route('POST', '/login/([^/]+)/consume', (req, res, b, m) => {
  const r = state.requests.find((x) => x.id === m[1]);
  if (!r) return send(res, 404, { code: 'not_found' });
  if (r.status !== 'CONFIRMED') return send(res, 409, { code: r.status === 'REJECTED' ? 'rejected' : r.status === 'EXPIRED' ? 'expired' : 'not_approved' });
  if (r.consumed) return send(res, 409, { code: 'already_used' });
  if (r.revokedAt) return send(res, 409, { code: 'revoked' });
  r.consumed = true;
  send(res, 200, {
    consumed: true, requestId: r.id, externalUsername: r.user, type: r.type, referenceId: r.referenceId, details: r.details,
    confirmedVia: r.confirmedVia, assurance: assurance(r), approvalProof: null, ...shieldFields(r),
  });
});
route('POST', '/login/([^/]+)/report-fraud', (req, res, b, m) => {
  const r = state.requests.find((x) => x.id === m[1]);
  if (!r) return send(res, 404, { code: 'not_found' });
  const reason = b.reason === undefined ? 'other' : b.reason;
  if (!['chargeback', 'account_takeover', 'social_engineering', 'other'].includes(reason)) return send(res, 400, { code: 'invalid_reason' });
  if (b.note !== undefined && (typeof b.note !== 'string' || b.note.length > 500)) return send(res, 400, { code: 'invalid_note' });
  const alreadyReported = Boolean(r.fraudReported);
  r.fraudReported = { reason, note: b.note || null };
  send(res, 200, { reported: true, alreadyReported, requestId: r.id });
});
route('POST', '/login/recovery', (req, res, b) => send(res, 200, { success: true }));
// Silent sign-ins. Sends nothing to the phone; never 404 for an unknown user (that would reveal who has 2FA).
route('POST', '/risk/check', (req, res, b) => {
  state.lastCheck = b;
  if (typeof b.externalUsername !== 'string' || !b.externalUsername) return send(res, 400, { code: 'invalid_request', error: 'externalUsername is required' });
  if (state.opts.rateLimited) return send(res, 429, { code: 'rate_limited', error: 'too_many_login_requests', retryAfter: 60 }, { 'Retry-After': '60' });
  const ask = (assurance, ...codes) => send(res, 200, { prompt: true, reasons: reasons(...codes), assurance, silentMode: 'enforce', caseCode: 'CHK-2QX' });
  if (!state.linked.has(b.externalUsername)) return ask('normal', 'phone_not_linked');
  if ((state.actions.get(b.type || 'LOGIN') || {}).critical) return ask('normal', 'critical_action');
  if (state.opts.silent) {
    return send(res, 200, {
      prompt: false, reasons: reasons('known_browser', 'recent_approval', 'same_phone', 'familiar_network', 'no_risk_signal'), assurance: 'high', silentMode: 'enforce',
      caseCode: 'CHK-2QX',
    });
  }
  return ask('normal', b.browserProof ? 'new_browser' : 'no_browser_key');
});
const browserView = ({ user, ...rest }) => rest;
route('GET', '/risk/browsers', (req, res) => {
  const user = new URL(req.url, 'http://x').searchParams.get('externalUsername');
  if (!user) return send(res, 400, { code: 'invalid_request', error: 'externalUsername is required' });
  send(res, 200, { browsers: state.browsers.filter((x) => x.user === user).map(browserView) });
});
route('POST', '/risk/browsers/forget', (req, res, b) => {
  if (typeof b.externalUsername !== 'string' || !b.externalUsername) return send(res, 400, { code: 'invalid_request', error: 'externalUsername is required' });
  const gone = (x) => x.user === b.externalUsername && (!b.thumbprint || x.thumbprint === b.thumbprint);
  const forgotten = state.browsers.filter(gone).length;
  state.browsers = state.browsers.filter((x) => !gone(x));
  send(res, 200, { forgotten });
});
// Never Locked Out: vouchers and recovery cases (a linked user can vouch).
const voucherView = (user) => ({
  externalUsername: user,
  vouchers: (state.vouchers.get(user) || []).map((v) => (state.linked.has(v) ? { externalUsername: v, eligible: true } : { externalUsername: v, eligible: false, reason: 'no_phone' })),
  updatedAt: null,
  probationUntil: null,
});
const RECOVERY_OPEN = ['AWAITING_DEVICE', 'VOUCHING', 'COOLING'];
const recoveryView = ({ bindCode, bindUri, ...c }) => c;
route('POST', '/recovery/vouchers', (req, res, b) => {
  if (typeof b.externalUsername !== 'string' || !b.externalUsername || !Array.isArray(b.vouchers)) return send(res, 400, { code: 'invalid_request', error: 'externalUsername and vouchers are required' });
  if (!state.linked.has(b.externalUsername) && !state.pending.has(b.externalUsername)) return send(res, 404, { code: 'user_not_found', error: 'No TouchQue user with this externalUsername' });
  state.vouchers.set(b.externalUsername, [...new Set(b.vouchers.filter((v) => typeof v === 'string' && v && v !== b.externalUsername))].slice(0, 5));
  send(res, 200, voucherView(b.externalUsername));
});
route('GET', '/recovery/vouchers', (req, res) => {
  const user = new URL(req.url, 'http://x').searchParams.get('externalUsername');
  if (!user) return send(res, 400, { code: 'invalid_request', error: 'externalUsername is required' });
  if (!state.linked.has(user) && !state.pending.has(user)) return send(res, 404, { code: 'user_not_found', error: 'No TouchQue user with this externalUsername' });
  send(res, 200, voucherView(user));
});
route('POST', '/recovery/start', (req, res, b) => {
  const user = b.externalUsername;
  if (typeof user !== 'string' || !user) return send(res, 400, { code: 'invalid_request', error: 'externalUsername is required' });
  if (!state.linked.has(user)) return send(res, 404, { code: 'device_not_linked', error: 'This user has no linked phone' });
  if (state.opts.blocked) return send(res, 403, { code: 'blocked', reason: 'risk', error: 'blocked' });
  const open = state.recoveries.find((c) => c.externalUsername === user && RECOVERY_OPEN.includes(c.status) && c.status !== 'AWAITING_DEVICE');
  if (open) return send(res, 409, { code: 'recovery_in_progress', recoveryId: open.recoveryId, error: 'A recovery for this user is already running.' });
  const required = Math.max(2, Number(b.required) || 0);
  const pool = [...(state.vouchers.get(user) || []), ...(Array.isArray(b.fallbackVouchers) ? b.fallbackVouchers : [])];
  const eligible = [...new Set(pool)].filter((v) => v !== user && state.linked.has(v)).slice(0, 5);
  if (eligible.length < required) return send(res, 409, { code: 'not_enough_vouchers', required, eligible: eligible.length, error: 'Not enough vouchers' });
  const id = `00000000-0000-4000-9000-${String(++state.seq).padStart(12, '0')}`;
  const bindCode = `bind-${state.seq}`;
  const c = {
    recoveryId: id, externalUsername: user, method: 'vouch', status: 'AWAITING_DEVICE', required, approvals: 0,
    vouchers: eligible.map((v) => ({ externalUsername: v, source: (state.vouchers.get(user) || []).includes(v) ? 'nominated' : 'fallback', state: 'waiting', code: null })),
    oldPhone: { notified: false, code: null }, coolOffMinutes: Math.max(15, Number(b.coolOffMinutes) || 60), coolOffUntil: null,
    elevated: false, reasons: [], location: null, newPhoneBound: false, expiresAt: new Date(Date.now() + 900000).toISOString(),
    completedAt: null, endedReason: null, endedBy: null, createdAt: new Date().toISOString(), receipts: [],
  };
  state.recoveries.push(c);
  send(res, 201, { ...c, bindCode, bindUri: `touchque://recover?id=${id}&code=${bindCode}`, riskContext: { level: 'none', reasons: [] } });
});
route('GET', '/recovery', (req, res) => {
  const q = new URL(req.url, 'http://x').searchParams;
  const user = q.get('externalUsername');
  const open = q.get('open') === 'true';
  if (!user && !open) return send(res, 400, { code: 'invalid_request', error: 'Pass externalUsername, or open=true' });
  const list = state.recoveries.filter((c) => (!user || c.externalUsername === user) && (!open || RECOVERY_OPEN.includes(c.status)));
  send(res, 200, { recoveries: list.slice().reverse().map(recoveryView) });
});
route('GET', '/recovery/([^/]+)', (req, res, b, m) => {
  const c = state.recoveries.find((x) => x.recoveryId === decodeURIComponent(m[1]));
  if (!c) return send(res, 404, { code: 'recovery_not_found', error: 'Recovery not found' });
  send(res, 200, recoveryView(c));
});
route('POST', '/recovery/([^/]+)/veto', (req, res, b, m) => {
  const c = state.recoveries.find((x) => x.recoveryId === decodeURIComponent(m[1]));
  if (!c) return send(res, 404, { code: 'recovery_not_found', error: 'Recovery not found' });
  if (!RECOVERY_OPEN.includes(c.status)) return send(res, 409, { code: 'recovery_not_open', status: c.status, error: `This recovery is already ${c.status.toLowerCase()}` });
  Object.assign(c, { status: 'VETOED', endedReason: b.reason || 'partner_veto', endedBy: b.by || 'partner' });
  send(res, 200, recoveryView(c));
});

// ── TouchQue Actions (in memory; nothing runs) ──
const TRIGGERS = ['login.request', 'risk.check', 'approval.decided', 'shield.decision', 'fraud.reported', 'device.linked', 'device.keys_lost', 'user.unlinked', 'passkey.added', 'passkey.removed', 'recovery.updated'];
const flowView = (a) => ({ slug: a.slug, name: a.name, trigger: a.trigger, enabled: a.enabled, order: a.order, onFailure: a.onFailure, activeVersion: a.activeVersion, createdAt: a.createdAt, updatedAt: a.updatedAt });
const versionView = (a, v, withCode = false) => {
  const { key, code, ...rest } = v;
  return { ...rest, active: a.activeVersion === v.number, ...(withCode && { code }) };
};
const flowOf = (res, slug) => {
  const a = state.flows.get(decodeURIComponent(slug));
  if (!a) send(res, 404, { code: 'action_not_found', error: `No Action named ${slug}.` });
  return a;
};
route('GET', '/actions/triggers', (req, res) => send(res, 200, {
  triggers: TRIGGERS.map((name) => ({ name, phase: name === 'login.request' || name === 'risk.check' ? 'pre' : 'post', decisions: [], effects: [], capabilities: [] })),
  capabilities: [{ name: 'skip_number_match', trigger: 'login.request' }, { name: 'override_block', trigger: 'login.request' }, { name: 'allow_silent', trigger: 'risk.check' }],
  limits: { cpuMs: 50, memoryMb: 16, preTriggerBudgetMs: 300 },
}));
route('GET', '/actions/templates', (req, res) => send(res, 200, { templates: ['alert', 'block_or_step_up', 'require_passkey_for_role', 'always_ask_when'].map((id) => ({ id, name: id, description: '', triggers: TRIGGERS, params: {} })) }));
route('POST', '/actions/templates/([^/]+)/render', (req, res, b, m) => {
  if (!TRIGGERS.includes(b.trigger)) return send(res, 400, { code: 'invalid_request', error: 'trigger is required' });
  send(res, 200, { code: `// Made with the "${m[1]}" template.\nexports.onExecute = async (event, api) => {};\n`, secrets: m[1] === 'alert' ? ['SLACK_WEBHOOK_URL'] : [], allowedHosts: [], capabilities: [] });
});
route('GET', '/actions/secrets', (req, res) => send(res, 200, { secrets: [...state.secrets.values()].map(({ value, ...rest }) => rest).sort((x, y) => x.name.localeCompare(y.name)) }));
route('PUT', '/actions/secrets/([^/]+)', (req, res, b, m) => {
  if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(m[1])) return send(res, 400, { code: 'invalid_request', error: 'bad secret name' });
  if (typeof b.value !== 'string' || !b.value) return send(res, 400, { code: 'invalid_request', error: 'value is required' });
  const now = new Date().toISOString();
  const had = state.secrets.get(m[1]);
  state.secrets.set(m[1], { name: m[1], value: b.value, createdAt: had ? had.createdAt : now, updatedAt: now });
  const { value, ...view } = state.secrets.get(m[1]);
  send(res, had ? 200 : 201, view);
});
route('DELETE', '/actions/secrets/([^/]+)', (req, res, b, m) => (state.secrets.delete(m[1])
  ? send(res, 200, { deleted: true }) : send(res, 404, { code: 'secret_not_found', error: `No secret named ${m[1]}.` })));
route('GET', '/actions/events', (req, res) => send(res, 200, { events: [] }));
route('POST', '/actions/test', (req, res, b) => send(res, 200, {
  outcome: 'ok', error: null, durationMs: 1, cpuMs: 0.5, calls: [], notifications: [], logs: [], reasons: [], wouldBe: null,
  eventId: b.eventId || null, event: b.event || {}, assumedCapabilities: b.capabilities || [], note: 'Notifications are not sent by a test run.',
}));
route('POST', '/actions/dry-run', (req, res, b) => send(res, 200, {
  trigger: b.trigger || null, evaluated: 0, from: null, to: null, matched: 0, changed: 0, transitions: {}, notifications: {}, errors: 0, timeouts: 0,
  errorSamples: [], p50Ms: 0, p95Ms: 0, samples: [], assumedCapabilities: b.capabilities || [],
}));
route('GET', '/actions', (req, res) => send(res, 200, {
  actions: [...state.flows.values()].map((a) => ({ ...flowView(a), pendingApproval: a.versions.filter((v) => v.status === 'pending_approval').length })),
}));
route('PUT', '/actions/([a-z0-9][a-z0-9-]{1,62})', (req, res, b, m) => {
  const slug = m[1];
  const existing = state.flows.get(slug);
  if (existing && b.trigger !== undefined && b.trigger !== existing.trigger) return send(res, 409, { code: 'trigger_mismatch', error: `${slug} runs on ${existing.trigger}` });
  const trigger = existing ? existing.trigger : b.trigger;
  if (!TRIGGERS.includes(trigger)) return send(res, 400, { code: 'invalid_request', error: 'trigger is required' });
  const code = b.code !== undefined ? b.code : (b.template ? `// template ${b.template.id}\nexports.onExecute = async () => {};\n` : undefined);
  if (typeof code !== 'string' || !code.trim()) return send(res, 400, { code: 'invalid_request', error: 'code is required' });
  if (/^\s*exports\.onExecute\s*=\s*\{\s*$/.test(code)) return send(res, 400, { code: 'action_invalid', error: 'SyntaxError' });
  const now = new Date().toISOString();
  const a = existing || { slug, name: slug, trigger, enabled: true, order: 100, onFailure: 'continue', activeVersion: null, versions: [], createdAt: now };
  const capabilities = b.capabilities || [];
  const key = JSON.stringify({ code, capabilities, allowedHosts: b.allowedHosts || [], secrets: b.secrets || [] });
  let v = a.versions[a.versions.length - 1];
  if (!v || v.key !== key) {
    v = {
      number: a.versions.length + 1, key, code, codeHash: sha256(key), capabilities, approvedCapabilities: [],
      allowedHosts: b.allowedHosts || [], secrets: b.secrets || [], template: b.template || null,
      status: capabilities.length ? 'pending_approval' : 'ready', createdAt: now, createdBy: 'api:test', approvedAt: null,
    };
    a.versions.push(v);
  }
  if (b.activate !== false && v.status === 'ready') a.activeVersion = v.number;
  for (const k of ['name', 'order', 'enabled', 'onFailure']) if (b[k] !== undefined) a[k] = b[k];
  a.updatedAt = now;
  state.flows.set(slug, a);
  send(res, existing ? 200 : 201, {
    action: flowView(a), version: versionView(a, v), deployed: a.activeVersion === v.number,
    approval: v.status === 'pending_approval' ? { required: true, capabilities: v.capabilities, message: 'Waits for an admin\'s phone approval in the dashboard.' } : null,
    warnings: [],
  });
});
route('GET', '/actions/([a-z0-9][a-z0-9-]{1,62})', (req, res, b, m) => {
  const a = flowOf(res, m[1]);
  if (!a) return;
  const active = a.versions.find((v) => v.number === a.activeVersion);
  send(res, 200, { action: flowView(a), code: (active || a.versions[a.versions.length - 1] || {}).code || null, versions: [...a.versions].reverse().map((v) => versionView(a, v)) });
});
route('PATCH', '/actions/([a-z0-9][a-z0-9-]{1,62})', (req, res, b, m) => {
  const a = flowOf(res, m[1]);
  if (!a) return;
  for (const k of ['name', 'order', 'enabled', 'onFailure']) if (b[k] !== undefined) a[k] = b[k];
  send(res, 200, { action: flowView(a) });
});
route('DELETE', '/actions/([a-z0-9][a-z0-9-]{1,62})', (req, res, b, m) => {
  const a = flowOf(res, m[1]);
  if (!a) return;
  state.flows.delete(a.slug);
  send(res, 200, { deleted: true });
});
route('POST', '/actions/([a-z0-9][a-z0-9-]{1,62})/rollback', (req, res, b, m) => {
  const a = flowOf(res, m[1]);
  if (!a) return;
  const target = b.version !== undefined
    ? a.versions.find((v) => v.number === b.version)
    : [...a.versions].reverse().find((v) => v.status === 'ready' && v.number < (a.activeVersion || Infinity)) || a.versions.find((v) => v.number === a.activeVersion);
  if (!target) return send(res, 404, { code: 'version_not_found', error: 'No such version.' });
  if (target.status !== 'ready') return send(res, 409, { code: 'version_not_runnable', error: `Version ${target.number} is ${target.status}.` });
  a.activeVersion = target.number;
  send(res, 200, { action: flowView(a), version: versionView(a, target) });
});
route('GET', '/actions/([a-z0-9][a-z0-9-]{1,62})/versions/([^/]+)', (req, res, b, m) => {
  const a = flowOf(res, m[1]);
  if (!a) return;
  const v = a.versions.find((x) => x.number === Number(m[2]));
  if (!v) return send(res, 404, { code: 'version_not_found', error: 'No such version.' });
  send(res, 200, versionView(a, v, true));
});
route('GET', '/actions/([a-z0-9][a-z0-9-]{1,62})/logs', (req, res, b, m) => { if (flowOf(res, m[1])) send(res, 200, { logs: [] }); });
route('GET', '/actions/([a-z0-9][a-z0-9-]{1,62})/metrics', (req, res, b, m) => {
  if (!flowOf(res, m[1])) return;
  const window = new URL(req.url, 'http://x').searchParams.get('window') || '24h';
  send(res, 200, { window, runs: 0, errors: 0, timeouts: 0, errorRate: 0, p50Ms: 0, p95Ms: 0, decisions: {}, notifications: { sent: 0, failed: 0, skipped: 0 } });});
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
  if (linked && linked.requiresPasskey) return send(res, 403, { error: 'passkey_required', reason: 'passkey_required' });
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
  if (ch.requestId && (state.requests.find((x) => x.id === ch.requestId) || {}).requiresPasskey) return send(res, 403, { approved: false, reason: 'passkey_required' });
  if (b.code !== 'ABCD123') return send(res, 401, { approved: false, reason: 'invalid_code', attemptsLeft: 4 });
  ch.used = true;
  send(res, 200, { approved: true, challengeId: b.challengeId, externalUsername: ch.user, type: ch.type });
});
route('POST', '/offline/totp/verify', (req, res, b) => {
  if (b.requestId && (state.requests.find((x) => x.id === b.requestId) || {}).status === 'REJECTED') return send(res, 410, { approved: false, reason: 'request_rejected' });
  if (b.requestId && (state.requests.find((x) => x.id === b.requestId) || {}).requiresPasskey) return send(res, 403, { approved: false, reason: 'passkey_required' });
  if (b.code !== '123456') return send(res, 401, { approved: false, reason: 'invalid_code' });
  send(res, 200, { approved: true, externalUsername: b.externalUsername });
});
// Like the API: a user with a linked phone needs an approved PASSKEY_ENROLL first, used once.
route('POST', '/webauthn/register/options', (req, res, b) => {
  const { externalUsername: user, approvalRequestId } = b;
  if (state.linked.has(user)) {
    if (!approvalRequestId) return send(res, 403, { code: 'enrollment_approval_required', error: 'enrollment_approval_required', action: 'PASSKEY_ENROLL' });
    const r = state.requests.find((x) => x.id === approvalRequestId);
    if (!r || r.user !== user || r.type !== 'PASSKEY_ENROLL' || r.status !== 'CONFIRMED') return send(res, 403, { code: 'enrollment_approval_invalid', error: 'enrollment_approval_invalid' });
    if (state.usedEnrollApprovals.has(r.id)) return send(res, 403, { code: 'enrollment_approval_used', error: 'enrollment_approval_used' });
    state.usedEnrollApprovals.add(r.id);
  }
  send(res, 200, { challenge: 'reg-challenge', rp: { id: 'example.com', name: 'Example' }, user: { name: user } });
});
route('GET', '/webauthn/credentials', (req, res) => send(res, 200, { credentials: [] }));
// Like the API since 3.3.0: the user the passkey belongs to is required.
route('DELETE', '/webauthn/credentials/([^/]+)', (req, res) => (new URL(req.url, 'http://x').searchParams.get('externalUsername')
  ? send(res, 200, { deleted: true })
  : send(res, 400, { code: 'invalid_request', error: 'externalUsername is required' })));

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
