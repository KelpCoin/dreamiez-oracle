const crypto = require('crypto');
const { verifyEvent, canonicalize } = require('./verify-event');

function hashEvent(event) {
  const copy = JSON.parse(JSON.stringify(event));
  delete copy.signature;
  return crypto.createHash('sha256').update(canonicalize(copy), 'utf8').digest('hex');
}

function verifyChain(events, publicKey, options = {}) {
  if (!Array.isArray(events) || events.length === 0) return { ok:false, reason:'EMPTY_CHAIN' };
  const seen = new Set();
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if (!e || typeof e !== 'object') return { ok:false, reason:'INVALID_EVENT' };
    if (seen.has(e.event_id)) return { ok:false, reason:'REPLAYED_EVENT' };
    seen.add(e.event_id);
    if (!verifyEvent(e, publicKey, options)) return { ok:false, reason:'EVENT_INVALID' };
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
