# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Dragon Vault, please report it by
creating a GitHub Issue with the title prefix `[security]`.

**Do not** disclose the vulnerability publicly until it has been addressed.

## Scope

### In Scope
- Authentication bypass or privilege escalation
- Cryptographic weaknesses (key derivation, encryption, AAD binding)
- Server-side injection (SQL injection, XSS via stored ciphertext)
- Passkey / WebAuthn ceremony vulnerabilities
- Session management flaws
- CSP bypass

### Out of Scope
- Deployment misconfigurations (nginx, certbot, SQL Server, file permissions)
- Brute-force attacks on the master password (Argon2id limits this)
- Physical access to the server
- Denial-of-service attacks
- Social engineering

## Response Timeline

- **Acknowledgment**: Within 7 days of report
- **Initial assessment**: Within 14 days
- **Fix**: Depends on severity; critical issues prioritized for immediate patch

## Security Model

Dragon Vault is a **zero-knowledge** password manager:

- The server never sees the master password, recovery code, or encryption key
- All key derivation (Argon2id) and encryption (AES-GCM 256) happens in the browser
- The server stores only ciphertext blobs and verifier material
- AAD (Additional Authenticated Data) binds every encrypted blob to the user and entry
- The CSP restricts `connect-src` to `'self'` and `api.pwnedpasswords.com`

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full crypto design.

## Dependencies

Critical dependencies are vendored (self-hosted) per REQ-053:

- `hash-wasm` (Argon2id WASM) — `wwwroot/js/vendor/hash-wasm.umd.min.js`
- `zxcvbn` (password strength) — `wwwroot/js/vendor/zxcvbn.js`

All other dependencies are NuGet packages pinned via `Directory.Packages.props`.
