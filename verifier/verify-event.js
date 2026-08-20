const crypto = require('crypto');

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

function verifyEvent(event, publicKey) {
  if (!event || typeof event !== 'object' || typeof event.signature !== 'string') return false;
  const sig = Buffer.from(event.signature, 'base64');
  return crypto.verify(null, signingBytes(event), publicKey, sig);
}

module.exports = { canonicalize, signingBytes, verifyEvent };

if (require.main === module) {
  const fs = require('fs');
  const path = process.argv[2];
  if (!path) { console.error('usage: node verify-event.js event.json'); process.exit(2); }
  const event = JSON.parse(fs.readFileSync(path, 'utf8'));
  const pem = fs.readFileSync(process.argv[3] || 'public.pem', 'utf8');
  const ok = verifyEvent(event, crypto.createPublicKey(pem));
  console.log(ok ? 'SIGNATURE_VALID' : 'SIGNATURE_INVALID');
  process.exit(ok ? 0 : 1);
}
