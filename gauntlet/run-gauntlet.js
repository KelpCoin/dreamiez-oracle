const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { canonicalize, verifyEvent } = require('../verifier/verify-event');
const { verifyChain, hashEvent } = require('../verifier/verify-chain');

function sign(event, privateKey) {
  const unsigned = JSON.parse(JSON.stringify(event));
  delete unsigned.signature;
  const signature = crypto.sign(null, Buffer.from(canonicalize(unsigned), 'utf8'), privateKey).toString('base64');
  return Object.assign({}, unsigned, { signature });
}

function clone(x) { return JSON.parse(JSON.stringify(x)); }

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const now = new Date().toISOString();

const e1 = sign({
  event_id:'evt_000001', event_type:'ORACLE_BOOTSTRAP', timestamp_utc:now,
  subject_id:'did:web:dreamiez.org', issuer_id:'did:web:dreamiez.org',
  previous_event_hash:null, payload:{status:'TRUST_ORACLE_INITIALIZED', methodology:'DATP-SCORE-0.1'}
}, privateKey);

const e2 = sign({
  event_id:'evt_000002', event_type:'CORRECTION', timestamp_utc:now,
  subject_id:'did:web:dreamiez.org', issuer_id:'did:web:dreamiez.org',
  previous_event_hash:hashEvent(e1), payload:{corrects:'evt_000001'}
}, privateKey);

const cases = [];
function test(name, fn) {
  try { fn(); cases.push({name,status:'PASS'}); }
  catch (err) { cases.push({name,status:'FAIL',error:err.message}); }
}

test('VALID EVENT', () => assert.strictEqual(verifyEvent(e1, publicKey), true));
test('PAYLOAD MODIFIED', () => { const x=clone(e1); x.payload.status='EVIL'; assert.strictEqual(verifyEvent(x, publicKey), false); });
test('SIGNATURE MODIFIED', () => { const x=clone(e1); x.signature=x.signature.slice(0,-2)+'AA'; assert.strictEqual(verifyEvent(x, publicKey), false); });
test('ISSUER MODIFIED AND RESIGNED', () => { const x=clone(e1); x.issuer_id='did:web:attacker.example'; const y=sign(x, privateKey); assert.strictEqual(verifyEvent(y, publicKey), false); });
test('EVENT ID MODIFIED', () => { const x=clone(e1); x.event_id='evt_999999'; assert.strictEqual(verifyEvent(x, publicKey), false); });
test('PREVIOUS HASH MODIFIED AND RESIGNED', () => { const x=clone(e2); x.previous_event_hash='00'.repeat(32); const y=sign(x, privateKey); assert.strictEqual(verifyChain([e1,y], publicKey).ok, false); });
test('CHAIN ORDER MODIFIED', () => { const r=verifyChain([e2,e1], publicKey); assert.strictEqual(r.ok, false); });
test('REPLAYED EVENT', () => { const r=verifyChain([e1,e1], publicKey); assert.strictEqual(r.ok, false); assert.strictEqual(r.reason,'REPLAYED_EVENT'); });
test('UNKNOWN METHODOLOGY AND RESIGNED', () => { const x=clone(e1); x.payload.methodology='UNKNOWN'; const y=sign(x, privateKey); assert.strictEqual(verifyEvent(y, publicKey), false); });
test('CORRECTION EVENT', () => { const r=verifyChain([e1,e2], publicKey); assert.strictEqual(r.ok, true); });
test('EMPTY CHAIN', () => { const r=verifyChain([], publicKey); assert.strictEqual(r.ok, false); assert.strictEqual(r.reason,'EMPTY_CHAIN'); });

const failed = cases.filter(x => x.status !== 'PASS');
const result = {
  gauntlet:'G0',
  generated_key:'EPHEMERAL_TEST_ONLY',
  dependency:'NONE_ON_DREAMLEDGER',
  verifier:'INDEPENDENT',
  tests:cases,
  result:failed.length===0?'PASS':'FAIL'
};

const proofDir = path.join(__dirname, '..', 'proof');
fs.mkdirSync(proofDir, { recursive:true });
fs.writeFileSync(path.join(proofDir, 'g0-result.json'), JSON.stringify(result, null, 2) + '\n', 'utf8');
console.log(JSON.stringify(result, null, 2));
process.exit(failed.length===0 ? 0 : 1);
