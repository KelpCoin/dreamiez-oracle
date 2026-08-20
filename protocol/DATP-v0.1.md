# Dreamiez Agent Trust Protocol (DATP) v0.1

## Purpose

DATP defines a portable evidence primitive for humans and autonomous agents participating in economic systems.

## Frozen objects

- IDENTITY
- EVENT
- ATTESTATION
- SCORE
- PASSPORT

## Fundamental rule

EVIDENCE != SCORE != DECISION

Dreamiez publishes evidence and deterministic derived calculations. A relying party chooses its own decision policy.

## Independence

A verifier MUST be able to validate a record using only the published verification material, the record, referenced history, and the published methodology. DreamLedger is not part of the trust root.

## Append-only history

Events are immutable. Corrections and challenges are new events that reference prior event hashes. Silent mutation is invalid.

## Cryptography

The v0.1 test profile uses Ed25519 signatures and SHA-256 hashes. Production key custody is deliberately outside this repository.

## Score transparency

A score MUST expose its value, confidence, methodology version, event count, timestamp, and provenance hash. A score is a derived view, never a statement of objective truth.
