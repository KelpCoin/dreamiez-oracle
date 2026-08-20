const crypto = require('crypto');

const DEFAULT_ISSUER = 'did:web:dreamiez.org';
const SUPPORTED_METHODOLOGIES = new Set(['DATP-SCORE-0.1']);

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

function signingBytes(event) {
  const copy = JSON.parse(JSON.stringify(event));
  delete copy.signature;
  return Buffer.from(canonicalize(copy), 'utf8');
}

function verifyEvent(event, publicKey, options = {}) {
  if (!event || typeof event !== 'object' || typeof event.signature !== 'string') return false;
  const issuer = options.issuer || DEFAULT_ISSUER;
  if (event.issuer_id !== issuer) return false;
  if (!event.event_id || !event.timestamp_utc || !event.subject_id) return false;
  const methodology = event.payload && event.payload.methodology;
  if (methodology !== undefined && !SUPPORTED_METHODOLOGIES.has(methodology)) return false;
  let sig;
  try { sig = Buffer.from(event.signature, 'base64'); } catch (_) { return false; }
  if (sig.length !== 64) return false;
  return crypto.verify(null, signingBytes(event), publicKey, sig);
}

module.exports = { canonicalize, signingBytes, verifyEvent, DEFAULT_ISSUER, SUPPORTED_METHODOLOGIES };

if (require.main === module) {
  const fs = require('fs');
  const path = process.argv[2];
  if (!path) { console.error('usage: node verify-event.js event.json [public.pem]'); process.exit(2); }
  const event = JSON.parse(fs.readFileSync(path, 'utf8'));
  const pem = fs.readFileSync(process.argv[3] || 'public.pem', 'utf8');
  const ok = verifyEvent(event, crypto.createPublicKey(pem));
  console.log(ok ? 'SIGNATURE_VALID' : 'SIGNATURE_INVALID');
  process.exit(ok ? 0 : 1);
}
