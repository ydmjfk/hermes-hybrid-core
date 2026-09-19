# Security Policy & Invariants

## Security Baseline: Public Release Ready

Hermes Hybrid Core follows strict defense-in-depth engineering principles. The core operates on explicit security invariants rather than unprovable absolute guarantees.

## Supported Versions

| Version | Supported          | Security Baseline |
| ------- | ------------------ | ----------------- |
| 1.0.x   | :white_check_mark: | Public Release Ready |
| 1.1.x   | :white_check_mark: | Industrial Robustness Edition |
| 1.2.x   | :white_check_mark: | Public Release Hardened Baseline |
| 1.3.x   | :white_check_mark: | Canonical Trust Architecture & Sandbox Parity |


---

## The 16 Security Invariants

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
* **INVARIANT-11 (Spool File POSIX & Symlink Hardening)**: All temporary file spooling mechanisms must enforce POSIX `0700` directory and `0600` file permissions. Spool directories and target files must be strictly validated against symlink substitution using `O_NOFOLLOW` and `is_symlink()` verification.
* **INVARIANT-12 (Spool Byte Budget & Concurrency Lock)**: Temporary spool files must have hard binary UTF-8 byte budgets with truncation markers factored in, and enforce concurrent directory quotas using advisory file locking (`flock`) to prevent multi-process DoS.
* **INVARIANT-13 (Bounded History & Spool Masking)**: Runtime duplicate call detectors and state caches must use bounded memory structures (`deque(maxlen=N)`). Spooled file paths must be masked by default (`mask_spool_path=True`) when communicating with language models or external consumers.
* **INVARIANT-14 (Background-Foreground Execution Parity & Sandbox Fail-Closed)**: Background processes must enforce the exact same security gates and sandbox confinement as foreground processes. Any failure in namespace creation, isolation adapter, or sandbox startup must strictly fail closed (return BLOCKED / exit code -1) without falling back to unconfined host execution.
* **INVARIANT-15 (Persistent Memory Anti-Taint & Anchor Protection)**: Persistent state and memory files (`MEMORY.md`, `USER.md`, `SOUL.md`) must reject adversarial prompt injection patterns (`ignore previous instructions`), shell payload markers, and tampering with immutable constitutional anchors. Mutating generic file tools (`write_file`, `patch`) must enforce persistent memory boundaries against direct or multi-file patch header (`*** Update/Move File:`) writes.
* **INVARIANT-16 (Decoupled Task Identity & Anti-Chaining Per-Job Whitelist)**: Scheduled and automated headless tasks must bind their verified task identity via session context variables. Task definition must be decoupled from execution authority (anti-self-authorization). All command evaluation must block unquoted shell command chaining operators (`;`, `&&`, `|`, `||`) and enforce strict exact/prefix whitelisting.


---

## Reporting a Vulnerability

We take the security and privacy of Hermes Hybrid Core seriously.

If you discover a security vulnerability or potential credential leakage:
1. **Do not open a public GitHub issue.**
2. Please privately disclose the vulnerability to the project maintainers via GitHub Security Advisories or by contacting the maintainer team directly.
3. Include detailed steps to reproduce the behavior, along with affected files and potential impact.

We will acknowledge receipt within 48 hours and coordinate remediation before public release.
