# Production bootstrap

No production issuer signature is present yet.

A production signing key must be generated in isolated custody. The private key must never enter this repository. The resulting public verification material and signed bootstrap event can then be published here.

The G0 Gauntlet currently uses an ephemeral in-memory Ed25519 key solely to prove the verifier and adversarial test machinery.
