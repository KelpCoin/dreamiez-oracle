const crypto = require('crypto');
const { verifyEvent } = require('./verify-event');

function hashEvent(event) {
  const copy = JSON.parse(JSON.stringify(event));
  delete copy.signature;
  return crypto.createHash('sha256').update(JSON.stringify(copy), 'utf8').digest('hex');
}

function verifyChain(events, publicKey) {
  const seen = new Set();
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if (seen.has(e.event_id)) return { ok:false, reason:'REPLAYED_EVENT' };
    seen.add(e.event_id);
    if (!verifyEvent(e, publicKey)) return { ok:false, reason:'SIGNATURE_INVALID' };
    if (i === 0) {
      if (e.previous_event_hash !== null) return { ok:false, reason:'BROKEN_GENESIS' };
    } else {
      const expected = hashEvent(events[i - 1]);
      if (e.previous_event_hash !== expected) return { ok:false, reason:'CHAIN_INVALID' };
    }
  }
  return { ok:true, reason:'CHAIN_VALID' };
}

module.exports = { hashEvent, verifyChain };
