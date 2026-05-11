# Architecture — Dragon Vault

## Threat Model

Dragon Vault assumes a **hostile server**. The server process, database, and
underlying OS are all untrusted. The browser is trusted (a compromised browser
can extract the encryption key from JS memory regardless of our mitigations).

**The server cannot decrypt vault data** — it never receives the master password,
recovery code, or encryption key. It stores only ciphertext blobs and verifier
material that are useless without the user's secrets.

## Zero-Knowledge Design

```
Browser                                  Server
--------                                 ------
master password                           |
  → Argon2id (WASM, 64 MB, 3 iter)       |
  → AES-GCM 256 bit key                   |
  → encrypt verifier plaintext            |
  → POST verifier ciphertext ────────────→ stored as opaque blob
                                           |
  ... later ...                            |
                                           |
  ← GET verifier ciphertext ───────────── |
  → derive key from password              |
  → AES-GCM decrypt verifier              |
  → if plaintext matches → unlocked       |
```

All encryption uses **AAD (Additional Authenticated Data)** binding: every
AES-GCM operation includes the user's ID and a purpose label (e.g.
`verifier-v1`, `recovery-wrap-v1`, `entry-field`) in the authenticated data.
This prevents cross-user and cross-purpose ciphertext swapping even if the
same key is used.

## Crypto Stack

| Component | Algorithm | Implementation |
|-----------|-----------|----------------|
| Key derivation | Argon2id (3 iter, 64 MB, 4 parallelism, 32 byte output) | hash-wasm (WASM, self-hosted) |
| Content encryption | AES-GCM 256 bit, per-field random IV (96 bit), 128 bit auth tag | Web Crypto API (`crypto.subtle`) |
| Key storage | CryptoKey (non-extractable) in JS module scope | Web Crypto API |
| Verifier | AES-GCM(encryption key, fixed 16-byte plaintext) | Web Crypto API |
| Recovery wrap | AES-GCM(recovery key, encryption key bytes) | Web Crypto API |
| Passkey wrap | AES-GCM(HKDF-SHA-256(prf/largeBlob secret), encryption key) | Web Crypto API + WebAuthn |
| Password strength | zxcvbn | Self-hosted |
| HIBP check | k-anonymity range query (5-char SHA-1 prefix) | `fetch` with `Add-Padding: true` |

## Authentication Flows

### First Sign-In (Setup)
1. User signs in with Google OAuth (authorization code flow, no PKCE)
2. Server checks email against configured allowlist
3. If first sign-in → redirect to `/Account/Setup`
4. Server generates per-user KDF salt + recovery salt, generates recovery code
5. Browser derives encryption key from master password (Argon2id)
6. Browser creates verifier blob (AES-GCM) and recovery wrap
7. Browser sends verifier + recovery wrap to server; server stores
8. Recovery code shown ONCE — user must save it

### Unlock
1. Server returns KDF parameters + verifier blob
2. User enters master password → browser derives key → decrypts verifier
3. If plaintext matches → key held in JS memory (non-extractable CryptoKey)
4. If passkey registered → auto-launches WebAuthn assertion → unwraps key

### Recovery
1. User enters 32-character recovery code
2. Browser derives recovery wrapping key from recovery code
3. Browser unwraps encryption key
4. User sets new master password → browser re-wraps everything

## Data Model

All sensitive fields in `VaultEntries` and `EntryFields` are stored as
ciphertext blobs on the server:

```
VaultEntry (server)
  NameCiphertext, NameIv, NameAuthTag       # AES-GCM encrypted
  UsernameCiphertext, ...                    # AES-GCM encrypted
  PasswordCiphertext, ...                    # AES-GCM encrypted
  UrlCiphertext, ...                         # AES-GCM encrypted
  NotesCiphertext, ...                       # AES-GCM encrypted
  TagsCiphertext, ...                        # AES-GCM encrypted
  PasswordHistoryJson                        # JSON array of previous passwords (encrypted)
  TagsNormalized                             # bit flag for tag normalization status

EntryField (server)
  Key                                        # plaintext (user-configurable field name)
  ValueCiphertext, ValueIv, ValueAuthTag    # AES-GCM encrypted
  FieldKind                                  # enum: password, totp_secret, note, custom
  SortOrder                                  # display ordering
```

## PWA Architecture

- **Service Worker** (`sw.js`): cache-first for static assets, network-first for
  navigation, network-only for API endpoints. Cache version key invalidates all
  caches on deploy.
- **Manifest** (`manifest.webmanifest`): `display: standalone`, full icon set
- **Offline**: static shell rendered when network unavailable
- **Session lock**: 15-minute idle timeout, tab-hidden detection, BroadcastChannel
  cross-tab coordination

## Deployment Topology

```
Internet → nginx (443, TLS 1.2/1.3)
           ├─ /sw.js → Kestrel (never cached)
           ├─ static/ → nginx (30-day cache)
           └─ /* → Kestrel (127.0.0.1:5000)
                    → SQL Server (127.0.0.1:1433, Docker)
```

- **Web server**: ASP.NET Core 10 Kestrel behind nginx reverse proxy
- **Database**: SQL Server 2022 (Docker)
- **TLS**: Let's Encrypt via certbot, auto-renewal
- **Process manager**: systemd (`dragonvault.service`)
- **Backup**: Nightly `BACKUP DATABASE` with compression + checksum, 7-day retention, optional rclone to Google Drive
- **Logging**: Serilog → stdout (systemd journal) + rolling file
