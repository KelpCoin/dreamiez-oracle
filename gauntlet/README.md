# G0 Gauntlet

Adversarial tests for the DATP v0.1 trust primitive.

Required cases:

- VALID EVENT -> PASS
- PAYLOAD MODIFIED -> REJECT
- SIGNATURE MODIFIED -> REJECT
- ISSUER MODIFIED -> REJECT
- EVENT ID MODIFIED -> REJECT
- PREVIOUS HASH MODIFIED -> REJECT
- CHAIN ORDER MODIFIED -> REJECT
- REPLAYED EVENT -> REJECT
- UNKNOWN METHODOLOGY -> REJECT/FLAG
- CORRECTION EVENT -> ACCEPT AS NEW EVENT

Run with a current Node.js runtime:

node gauntlet/run-gauntlet.js

The runner generates its Ed25519 key in memory. It does not read or write a private key file and does not contact DreamLedger.
