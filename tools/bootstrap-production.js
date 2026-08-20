const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const repoRoot = path.resolve(__dirname, '..');
const secretRoot = process.env.DREAMIEZ_SECRET_DIR || path.resolve(repoRoot, '..', 'DreamiezOracleSecrets');
const issuer = 'did:web:dreamiez.org';
const keyId = issuer + '#key-1';
const methodology = 'DATP-SCORE-0.1';

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(bytes) {
  let digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      const x = digits[i] * 256 + carry;
      digits[i] = x % 58;
      carry = Math.floor(x / 58);
    }
    while (carry) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let out = '';
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) out += '1';
  for (let i = digits.length - 1; i >= 0; i--) out += alphabet[digits[i]];
  return out;
}

function publicRaw32(publicKey) {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  if (der.length < 32) throw new Error('Unexpected Ed25519 public key encoding');
  return der.subarray(der.length - 32);
}

function assertOutsideRepo(filePath) {
  const rel = path.relative(repoRoot, path.resolve(filePath));
  if (!rel.startsWith('..') && !path.isAbsolute(rel)) {
    throw new Error('Refusing to write private key inside repository: ' + filePath);
  }
}

fs.mkdirSync(secretRoot, { recursive: true });
assertOutsideRepo(secretRoot);
const secretPath = path.join(secretRoot, 'issuer-private-key.pem');
const publicPath = path.join(secretRoot, 'issuer-public-key.pem');

if (fs.existsSync(secretPath) || fs.existsSync(publicPath)) {
  throw new Error('Refusing to overwrite existing production key material. Delete only after a deliberate key-rotation procedure.');
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
fs.writeFileSync(secretPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
fs.writeFileSync(publicPath, publicKey.export({ type: 'spki', format: 'pem' }));

const multibase = 'z' + base58(Buffer.concat([Buffer.from([0xed, 0x01]), publicRaw32(publicKey)]));
const did = {
  id: issuer,
  verificationMethod: [{
    id: keyId,
    type: 'Multikey',
    controller: issuer,
    publicKeyMultibase: multibase
  }],
  assertionMethod: [keyId]
};

const publicDidPath = path.join(repoRoot, 'public', '.well-known', 'did.json');
fs.mkdirSync(path.dirname(publicDidPath), { recursive: true });
fs.writeFileSync(publicDidPath, JSON.stringify(did, null, 2) + '\n');

const timestamp = new Date().toISOString();
const event = {
  event_id: 'evt_000001',
  event_type: 'ORACLE_BOOTSTRAP',
  timestamp_utc: timestamp,
  subject_id: issuer,
  issuer_id: issuer,
  previous_event_hash: null,
  payload: {
    status: 'TRUST_ORACLE_INITIALIZED',
    methodology,
    verification_method: keyId
  }
};
const signature = crypto.sign(null, Buffer.from(canonicalize(event), 'utf8'), privateKey).toString('base64');
const signed = Object.assign({}, event, { signature });
const eventPath = path.join(repoRoot, 'public', 'bootstrap', 'event-000001.json');
fs.mkdirSync(path.dirname(eventPath), { recursive: true });
fs.writeFileSync(eventPath, JSON.stringify(signed, null, 2) + '\n');

const keyInfo = { issuer, key_id: keyId, publicKeyMultibase: multibase, created_at: timestamp, private_key_path: secretPath };
fs.writeFileSync(path.join(secretRoot, 'KEY-CUSTODY.json'), JSON.stringify(keyInfo, null, 2) + '\n');
console.log(JSON.stringify({ ok: true, issuer, key_id: keyId, public_did: publicDidPath, bootstrap_event: eventPath, private_key: secretPath, warning: 'PRIVATE KEY WAS WRITTEN OUTSIDE THE REPOSITORY AND MUST NEVER BE COMMITTED' }, null, 2));
