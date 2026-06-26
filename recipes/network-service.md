# Recipe: network-service

## Applies to

Network daemons, protocol parsers, RPC services, web services, and IPC listeners.

## First-pass scope

Start with network input handling, protocol parsing, connection management, serialization/deserialization, authentication, and session handling. Avoid overfitting to a package type until the Package Profiler has higher confidence.

## High-risk inputs

- Protocol header fields (length, type, sequence numbers)
- Request/response bodies and their declared sizes
- Connection metadata (source address, port, TLS session)
- TLS/SSL handshake data and certificate chains
- DNS responses and resolution results
- Serialized/deserialized message payloads
- Timeout and keep-alive values
- Concurrent connection state and shared resources

## Primary tools

- `rg` for network-specific patterns: `recv`, `read` without bounds checks, `memcpy` with network-controlled lengths, `accept` without rate limiting
- Semgrep for unsafe deserialization, missing authentication on endpoints, hardcoded credentials
- CodeQL for dataflow from network input to memory operations
- AFL++ with protocol-aware mode for malformed input testing
- Package vulnerability scanners for known CVEs

## AI hypothesis focus

The hypothesis hunter should search for safety assumptions that traditional tools may miss:

- Protocol state machine inconsistency (unexpected state transitions)
- Integer overflow or underflow in length fields from network input
- Use-after-free on connection close or reset
- TOCTOU between request validation and processing
- Deserialization vulnerabilities (untrusted object reconstruction)
- DNS rebinding attacks bypassing origin checks
- HTTP request smuggling via header parsing inconsistency
- Race conditions in concurrent connection handling
- Missing authentication on internal-only endpoints exposed externally

## Candidate priority

Prioritize candidates involving attacker-controlled network data influencing allocation sizes, pointer arithmetic, state transitions, or authentication bypass.

## Recommended evidence

Every candidate must be grounded in real source path, function, line range, source-to-sink reasoning, and validation or a clear statement of missing validation.
