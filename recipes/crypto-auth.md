# Recipe: crypto-auth

## Applies to

Authentication, authorization, cryptography, key/certificate, and policy enforcement components.

## First-pass scope

Start with authentication entry points, cryptographic operations, key management, certificate handling, authorization checks, and session/token management. Avoid overfitting to a package type until the Package Profiler has higher confidence.

## High-risk inputs

- Key material (symmetric keys, private keys, seed values)
- IV/nonce values and their generation source
- Certificate chains and trust anchors
- Passwords, passphrases, and PINs
- Session tokens and API keys
- Signed data and signature values
- Timestamps used for expiry or replay protection
- Permission/assertion claims in tokens

## Primary tools

- `rg` for weak crypto patterns: `RAND_`, `srand`, `time(NULL)`, `memcmp` (password comparison), `MD5`, `SHA1` (non-HMAC), `DES`, `RC4`, hardcoded keys/seeds
- Semgrep for dangerous crypto APIs: ECB mode, static IVs, missing authentication
- CodeQL for dataflow from key material to output without proper derivation
- Package vulnerability scanners for known CVEs in crypto dependencies

## AI hypothesis focus

The hypothesis hunter should search for safety assumptions that traditional tools may miss:

- Timing side-channels in password or signature comparison (non-constant-time)
- Weak or predictable random number generation for keys/nonces/salts
- Insufficient key derivation (missing KDF, low iteration count, no salt)
- Padding oracle vulnerabilities in CBC-mode decryption
- Certificate chain validation bypass (missing expiry check, missing hostname verification, accepting self-signed)
- HMAC comparison using non-constant-time functions
- CBC bit-flipping when authentication is absent
- Nonce or IV reuse in stream ciphers or CTR/GCM modes
- Key material remaining in memory after use (missing zeroization)

## Candidate priority

Prioritize candidates involving attacker-controlled input reaching cryptographic decisions, key material exposure, missing authentication on encrypted data, or timing-dependent comparisons.

## Recommended evidence

Every candidate must be grounded in real source path, function, line range, source-to-sink reasoning, and validation or a clear statement of missing validation.
