# Security Policy & Invariants

## Security Baseline: Public Release Ready

Hermes Hybrid Core follows strict defense-in-depth engineering principles. The core operates on explicit security invariants rather than unprovable absolute guarantees.

## Supported Versions

| Version | Supported          | Security Baseline |
| ------- | ------------------ | ----------------- |
| 1.0.x   | :white_check_mark: | Public Release Ready |

---

## The 10 Security Invariants

All public releases must satisfy and enforce the following invariants:

* **INVARIANT-01 (Chat / File Exfiltration)**: All outbound file transfer APIs (`send_chat_file`) must pass through the `PathSanitizer` security gate. Unverified paths and `file://` bypass attempts are strictly blocked.
* **INVARIANT-02 (Recursive MCP Validation)**: Any input arguments passed to MCP tools must be recursively scanned across all nested structures (`dict`, `list`, `tuple`, `str`) for path traversal, shell injection, SQL mutation, and credentials.
* **INVARIANT-03 (Trusted Capability Execution & Human Approval)**: Dynamic capability extensions and mutating tools must verify manifest schema, path boundaries, SHA-256 file integrity, independent Ed25519 cryptographic Release Authority signatures, and cryptographically verified approval tokens or trusted approval handlers before execution. Untrusted callers cannot bypass human approval via self-declared boolean flags.
* **INVARIANT-04 (Objective Verifier)**: `UNKNOWN != PASS`. A test or validation result of UNKNOWN must never be treated as successful.
* **INVARIANT-05 (Fail-Closed Default)**: Any validation error, parsing failure, or security uncertainty must immediately Fail Closed.
* **INVARIANT-06 (Logger Sanitization)**: Secrets, raw private keys, tokens, and authorization credentials must never be written to plaintext loggers or exception strings.
* **INVARIANT-07 (Cache Sanitization)**: Raw secrets and authentication tokens must never enter persistent cache databases (e.g. SQLite query cache).
* **INVARIANT-08 (Cache Scope Isolation)**: Semantic cache entries must be isolated by `scope_id` and `caller_id`. User A and User B cannot access or leak responses across security scopes.
* **INVARIANT-09 (Zero Private Identifiers)**: The public repository must not contain real customer names, internal company names, private hostnames, or developer home directory layouts.
* **INVARIANT-10 (Release Gate Enforcement)**: Any security test failure, secret detection, or dependency vulnerability strictly blocks CI/CD release.

---

## Reporting a Vulnerability

We take the security and privacy of Hermes Hybrid Core seriously.

If you discover a security vulnerability or potential credential leakage:
1. **Do not open a public GitHub issue.**
2. Please privately disclose the vulnerability to the project maintainers via GitHub Security Advisories or by contacting the maintainer team directly.
3. Include detailed steps to reproduce the behavior, along with affected files and potential impact.

We will acknowledge receipt within 48 hours and coordinate remediation before public release.
