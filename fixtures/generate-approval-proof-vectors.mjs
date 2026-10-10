// Regenerates approval-proof-vectors.json (cross-SDK golden vectors for
// verifyApprovalProof / detailsDigest). Signatures are made with a throw-away
// P-256 key in the same wire format as the phones' Secure Enclave / Keystore
// key; only its public half is kept. Run: node fixtures/generate-approval-proof-vectors.mjs
import * as crypto from 'crypto';
import { writeFileSync } from 'fs';

const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const other = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const x963 = (pub) => {
  const jwk = pub.export({ format: 'jwk' });
  const b = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  return Buffer.concat([Buffer.from([4]), b(jwk.x), b(jwk.y)]).toString('base64');
};
const PUB = x963(publicKey);
const OTHER_PUB = x963(other.publicKey);

const pairs = (details) => (details || []).map((d) => ({ label: String(d.label).trim(), value: String(d.value).trim() }));
const digest = (details) => {
  const p = pairs(details);
  if (!p.length) return '';
  return crypto.createHash('sha256').update(p.map((x) => `${x.label}\u001F${x.value}`).join('\u001E'), 'utf8').digest('hex');
};
const message = (o) => ['touchque-approve:v2', o.requestId, o.type, o.challengeCode ?? '', digest(o.details)].join('\n');
const sign = (msg, key = privateKey) => crypto.sign('sha256', Buffer.from(msg, 'utf8'), { key, dsaEncoding: 'der' }).toString('base64');
const proof = (msg, { key = privateKey, pub = PUB } = {}) => ({ version: 'v2', algorithm: 'ECDSA-P256-SHA256', message: msg, signature: sign(msg, key), publicKey: pub });

const details = [{ label: 'Amount', value: '1,250.00 USD' }, { label: 'Recipient', value: 'Jane Doe' }];
const base = { requestId: 'req-1', type: 'WITHDRAW', challengeCode: '47', details };
const good = proof(message(base));
const unicode = [{ label: '  Empfänger ', value: ' Zoë Ångström  ' }, { label: 'Montant', value: '€12.500,00' }];
const uni = { requestId: 'req-ß', type: 'SEND_MONEY', details: unicode };

const cases = [
  { name: 'valid, pinned key', proof: good, options: { ...base, expectedPublicKey: PUB }, expected: true },
  { name: 'valid, trust on first use', proof: good, options: { ...base, allowUnpinnedKey: true }, expected: true },
  { name: 'no pin and no allowUnpinnedKey fails closed', proof: good, options: { ...base }, expected: false },
  { name: 'pinned to a different device', proof: good, options: { ...base, expectedPublicKey: OTHER_PUB }, expected: false },
  { name: 'other details than shown', proof: good, options: { ...base, details: [{ label: 'Amount', value: '9,999.00 USD' }, details[1]], expectedPublicKey: PUB }, expected: false },
  { name: 'other request id', proof: good, options: { ...base, requestId: 'req-2', expectedPublicKey: PUB }, expected: false },
  { name: 'other action type', proof: good, options: { ...base, type: 'LOGIN', expectedPublicKey: PUB }, expected: false },
  { name: 'other challenge code', proof: good, options: { ...base, challengeCode: '48', expectedPublicKey: PUB }, expected: false },
  { name: 'missing challenge code', proof: good, options: { ...base, challengeCode: undefined, expectedPublicKey: PUB }, expected: false },
  { name: 'message edited after signing', proof: { ...good, message: message({ ...base, type: 'LOGIN' }) }, options: { ...base, type: 'LOGIN', expectedPublicKey: PUB }, expected: false },
  { name: 'signature from another key, pinned key claimed', proof: { ...proof(message(base), { key: other.privateKey }), publicKey: PUB }, options: { ...base, expectedPublicKey: PUB }, expected: false },
  { name: 'corrupted signature', proof: { ...good, signature: Buffer.from('garbage-signature').toString('base64') }, options: { ...base, expectedPublicKey: PUB }, expected: false },
  { name: 'public key not an uncompressed P-256 point', proof: { ...good, publicKey: Buffer.alloc(65, 1).toString('base64') }, options: { ...base, allowUnpinnedKey: true }, expected: false },
  { name: 'wrong version', proof: { ...good, version: 'v1' }, options: { ...base, expectedPublicKey: PUB }, expected: false },
  { name: 'wrong algorithm', proof: { ...good, algorithm: 'ECDSA-P384-SHA384' }, options: { ...base, expectedPublicKey: PUB }, expected: false },
  { name: 'no details, no challenge code', proof: proof(message({ requestId: 'req-3', type: 'LOGIN' })), options: { requestId: 'req-3', type: 'LOGIN', expectedPublicKey: PUB }, expected: true },
  { name: 'unicode details, trimmed', proof: proof(message(uni)), options: { ...uni, expectedPublicKey: PUB }, expected: true },
  { name: 'null proof', proof: null, options: { ...base, expectedPublicKey: PUB }, expected: false },
];

const out = {
  description: 'Cross-SDK golden vectors for verifyApprovalProof / detailsDigest. Message: "touchque-approve:v2\\n{requestId}\\n{type}\\n{challengeCode}\\n{detailsDigest}"; ECDSA P-256 SHA-256, DER signature, X9.63 uncompressed base64 public key. Details are given as ordered {label,value} lists; digest_cases also cover the object form where a language keeps key order.',
  publicKey: PUB,
  digest_cases: [
    { details: details, digest: digest(details) },
    { details_object: { Amount: '1,250.00 USD', Recipient: 'Jane Doe' }, digest: digest(details) },
    { details: unicode, digest: digest(unicode) },
    { details: [], digest: '' },
  ],
  cases: cases.map((c) => ({ ...c, options: Object.fromEntries(Object.entries(c.options).filter(([, v]) => v !== undefined)) })),
};
writeFileSync(new URL('./approval-proof-vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${out.cases.length} cases, digest ${out.digest_cases[0].digest}`);
