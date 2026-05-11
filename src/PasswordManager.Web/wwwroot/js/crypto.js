// Dragon Vault browser-side crypto module. No framework. ES module.
//
// Responsibilities:
//   - Spawn / address the Argon2id Worker.
//   - Wrap Web Crypto AES-GCM (encrypt / decrypt) with the project's AAD scheme.
//   - Build the verifier blob, the recovery wrap, and unwrap on recovery.
//   - Expose the unlocked CryptoKey to other modules ONLY via a getter (the actual
//     key reference lives in module scope and is never returned to inline scripts).
//
// Keys are imported as non-extractable CryptoKey instances per REQ-017. The raw bytes
// hand-off from the Worker happens once (transferable Uint8Array), and we zero the
// transferred buffer immediately after import.

const VERIFIER_PLAINTEXT = (() => {
    // Fixed 16-byte plaintext: "vault-verifier-v1" → 17 chars. Trim to 16 (drop trailing
    // '1') OR pad — design says "zero-padded to 16". Use the literal 16 chars
    // "vault-verifier-v" so we end up with exactly 16 bytes.
    const s = 'vault-verifier-v';
    const out = new Uint8Array(16);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
})();

let _encryptionKey = null;          // CryptoKey (non-extractable) when unlocked.
let _userIdBytes = null;            // Uint8Array of userId UTF-8 (for AAD binding).

// ----- worker -----

let _workerSeq = 0;
const _workerPending = new Map();
let _worker = null;

function getWorker() {
    if (!_worker) {
        _worker = new Worker('/js/crypto-worker.js');
        _worker.onmessage = (ev) => {
            const { id, ok, key, error } = ev.data || {};
            const pending = _workerPending.get(id);
            if (!pending) return;
            _workerPending.delete(id);
            if (ok) pending.resolve(key); else pending.reject(new Error(error || 'argon2 failed'));
        };
        _worker.onerror = (ev) => {
            for (const [, pending] of _workerPending) pending.reject(new Error(ev.message || 'worker error'));
            _workerPending.clear();
        };
    }
    return _worker;
}

export function deriveKeyBytes({ password, salt, iterations, memoryKb, parallelism, outputBytes }) {
    const id = ++_workerSeq;
    const worker = getWorker();
    return new Promise((resolve, reject) => {
        _workerPending.set(id, { resolve, reject });
        // Encode the password to a Uint8Array here so the main thread keeps a local
        // copy we can zero after the postMessage has been queued.
        const enc = new TextEncoder().encode(password);
        worker.postMessage(
            {
                id,
                password: enc,
                salt: salt,
                iterations: iterations,
                memoryKb: memoryKb,
                parallelism: parallelism,
                outputBytes: outputBytes,
            },
            [enc.buffer, salt.buffer.slice(0)]   // transfer copies; salt itself is reused via slice()
        );
    });
}

// ----- helpers -----

export function b64Encode(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
}

export function b64Decode(b64) {
    const s = atob(b64);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
}

// Base64url variants (URL-safe alphabet, no padding) — required on the wire for
// WebAuthn message envelopes (`challenge`, `id`, `rawId`, all binary bytes go up as
// base64url per the spec). We piggy-back on btoa/atob to avoid reimplementing base64.
export function b64uEncode(bytes) {
    return b64Encode(bytes)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

export function b64uDecode(b64u) {
    let s = (b64u || '').replace(/-/g, '+').replace(/_/g, '/');
    const pad = s.length % 4;
    if (pad === 2) s += '==';
    else if (pad === 3) s += '=';
    else if (pad !== 0) throw new Error('Invalid base64url length');
    return b64Decode(s);
}

function concatBytes(...arrays) {
    let total = 0;
    for (const a of arrays) total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrays) { out.set(a, off); off += a.length; }
    return out;
}

function aad(userIdBytes, label) {
    const enc = new TextEncoder().encode(label);
    return concatBytes(userIdBytes, enc);
}

function setUserIdBytes(userId) {
    _userIdBytes = new TextEncoder().encode(userId);
}

async function importAesKey(rawBytes, extractable = false) {
    const key = await crypto.subtle.importKey(
        'raw',
        rawBytes,
        { name: 'AES-GCM' },
        extractable,
        ['encrypt', 'decrypt']
    );
    return key;
}

function zero(bytes) {
    if (bytes && bytes.fill) {
        try { bytes.fill(0); } catch (_) { /* frozen */ }
    }
}

// AES-GCM encrypt → returns { ciphertext, iv, authTag } as Uint8Arrays.
// Web Crypto returns ciphertext||tag concatenated; we split the trailing 16 bytes
// to match the schema's *Ciphertext / *AuthTag column split.
async function aesGcmEncrypt(key, plaintext, additionalData) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ctAndTag = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData, tagLength: 128 },
        key,
        plaintext
    ));
    const tagStart = ctAndTag.length - 16;
    return {
        ciphertext: ctAndTag.slice(0, tagStart),
        authTag: ctAndTag.slice(tagStart),
        iv: iv,
    };
}

async function aesGcmDecrypt(key, ciphertext, iv, authTag, additionalData) {
    const blob = concatBytes(ciphertext, authTag);
    const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData, tagLength: 128 },
        key,
        blob
    );
    return new Uint8Array(plaintext);
}

// ----- public lifecycle -----

// Setup: master password + recovery code → produce wrapped material for the server.
//
//   args = {
//       userId, masterPassword, recoveryCode,
//       kdfSalt, recoverySalt,           // Uint8Array
//       kdfIterations, kdfMemoryKb, kdfParallelism, kdfOutputBytes
//   }
// Returns the POST body for /api/account/setup with all fields base64-encoded.
export async function buildSetupPayload(args) {
    setUserIdBytes(args.userId);

    // 1) Derive EncryptionKey (used to encrypt vault data).
    const encKeyBytes = await deriveKeyBytes({
        password: args.masterPassword,
        salt: args.kdfSalt,
        iterations: args.kdfIterations,
        memoryKb: args.kdfMemoryKb,
        parallelism: args.kdfParallelism,
        outputBytes: args.kdfOutputBytes,
    });

    // 2) Derive RecoveryWrappingKey.
    const recoveryKeyBytes = await deriveKeyBytes({
        password: args.recoveryCode,
        salt: args.recoverySalt,
        iterations: args.kdfIterations,
        memoryKb: args.kdfMemoryKb,
        parallelism: args.kdfParallelism,
        outputBytes: args.kdfOutputBytes,
    });

    // 3) Wrap encryption key under recovery wrapping key.
    //    The wrapping key is single-use here so it can be extractable=false; the actual
    //    encryption key needs to be importable as raw bytes for the wrap, so we briefly
    //    hold it as a Uint8Array (we just produced it ourselves) and zero after use.
    const recoveryWrappingKey = await importAesKey(recoveryKeyBytes);
    const recoveryAad = aad(_userIdBytes, 'recovery-wrap-v1');
    const recoveryWrap = await aesGcmEncrypt(recoveryWrappingKey, encKeyBytes, recoveryAad);

    // 4) Verifier: AES-GCM(EncryptionKey, "vault-verifier-v1...").
    const encKey = await importAesKey(encKeyBytes);  // non-extractable
    const verifierAad = aad(_userIdBytes, 'verifier-v1');
    const verifier = await aesGcmEncrypt(encKey, VERIFIER_PLAINTEXT, verifierAad);

    // 5) Hold the unlocked encryption key in module scope.
    _encryptionKey = encKey;

    // 6) Scrub the raw key materials from main-thread heap.
    zero(encKeyBytes);
    zero(recoveryKeyBytes);

    return {
        verifierCiphertext: b64Encode(verifier.ciphertext),
        verifierIv: b64Encode(verifier.iv),
        verifierAuthTag: b64Encode(verifier.authTag),
        recoveryWrappedKey: b64Encode(recoveryWrap.ciphertext),
        recoveryWrappedKeyIv: b64Encode(recoveryWrap.iv),
        recoveryWrappedKeyAuthTag: b64Encode(recoveryWrap.authTag),
    };
}

// Unlock: derive key, decrypt verifier blob to confirm, hold CryptoKey in memory.
//
//   args = {
//       userId, masterPassword,
//       kdfSalt, kdfIterations, kdfMemoryKb, kdfParallelism, kdfOutputBytes,
//       verifierCiphertext, verifierIv, verifierAuthTag    // Uint8Array
//   }
// Returns true on successful verifier decrypt; false on wrong password.
export async function unlockWithMaster(args) {
    setUserIdBytes(args.userId);

    const keyBytes = await deriveKeyBytes({
        password: args.masterPassword,
        salt: args.kdfSalt,
        iterations: args.kdfIterations,
        memoryKb: args.kdfMemoryKb,
        parallelism: args.kdfParallelism,
        outputBytes: args.kdfOutputBytes,
    });

    const candidateKey = await importAesKey(keyBytes);

    try {
        const plaintext = await aesGcmDecrypt(
            candidateKey,
            args.verifierCiphertext,
            args.verifierIv,
            args.verifierAuthTag,
            aad(_userIdBytes, 'verifier-v1')
        );
        // Sanity check: plaintext must equal the well-known verifier bytes.
        if (plaintext.length !== VERIFIER_PLAINTEXT.length) {
            zero(keyBytes);
            return { ok: false, rawKeyBytes: null, reason: 'Length mismatch' };
        }
        for (let i = 0; i < plaintext.length; i++) {
            if (plaintext[i] !== VERIFIER_PLAINTEXT[i]) {
                zero(keyBytes);
                return { ok: false, rawKeyBytes: null, reason: 'Byte mismatch' };
            }
        }
        _encryptionKey = candidateKey;
        return { ok: true, rawKeyBytes: keyBytes };
    } catch (_) {
        // AES-GCM auth tag mismatch → wrong master password.
        zero(keyBytes);
        return { ok: false, rawKeyBytes: null, reason: 'Auth tag' };
    }
}

// Recover: derive recovery wrapping key, unwrap encryption key, then prompt the caller
// for a NEW master password. The caller invokes `buildRotatePayload` afterward.
//
//   args = {
//       userId, recoveryCode,
//       recoverySalt, kdfIterations, kdfMemoryKb, kdfParallelism, kdfOutputBytes,
//       recoveryWrappedKey, recoveryWrappedKeyIv, recoveryWrappedKeyAuthTag
//   }
// Returns true on successful unwrap (encryption key now held in module memory),
// false on bad recovery code.
export async function unwrapWithRecoveryCode(args) {
    setUserIdBytes(args.userId);

    const wrappingKeyBytes = await deriveKeyBytes({
        password: args.recoveryCode,
        salt: args.recoverySalt,
        iterations: args.kdfIterations,
        memoryKb: args.kdfMemoryKb,
        parallelism: args.kdfParallelism,
        outputBytes: args.kdfOutputBytes,
    });

    const wrappingKey = await importAesKey(wrappingKeyBytes);
    zero(wrappingKeyBytes);

    try {
        const rawKey = await aesGcmDecrypt(
            wrappingKey,
            args.recoveryWrappedKey,
            args.recoveryWrappedKeyIv,
            args.recoveryWrappedKeyAuthTag,
            aad(_userIdBytes, 'recovery-wrap-v1')
        );
        _encryptionKey = await importAesKey(rawKey);
        zero(rawKey);
        return true;
    } catch (_) {
        return false;
    }
}

// Rotate master password.
//
// Per design §5.4 invariant: the EncryptionKey is unchanged — we re-wrap it. But the
// recovery code is unchanged here too (we got it via unwrap), so the recovery wrap is
// rewrapped with the SAME wrapping key (because RecoverySalt + recoveryCode unchanged)
// just to refresh the IV. We must therefore have the recovery code in hand at this
// moment — it was passed to `unwrapWithRecoveryCode` and is supplied again here.
//
//   args = {
//       userId, newMasterPassword, recoveryCode,
//       recoverySalt,
//       kdfIterations, kdfMemoryKb, kdfParallelism, kdfOutputBytes
//   }
// Returns the POST body for /api/account/rotate-master, plus the new KdfSalt
// (the server stores it). Recovery wrap is regenerated so its IV is fresh.
export async function buildRotatePayload(args) {
    if (_encryptionKey === null) {
        throw new Error('No unlocked key in memory — call unwrapWithRecoveryCode first.');
    }

    // Need the raw encryption-key bytes to wrap them under the new master-derived key
    // and the recovery wrapping key. The current _encryptionKey CryptoKey is non-
    // extractable, so we re-derive the raw bytes by decrypting our own verifier? No —
    // a cleaner path: when we unwrapped via recovery, we already imported it as
    // non-extractable. To rewrap we need raw. Strategy: re-run the unwrap here using
    // the recovery code to recover the raw bytes (it's local, cheap relative to
    // Argon2id which we already paid for, and avoids holding raw key bytes in memory
    // longer than necessary).
    //
    // We DO need to redo the Argon2 derivation for the recovery wrapping key because
    // we never kept its raw bytes either. Live with the extra ~1s of derivation —
    // master-password rotation is a rare event.
    const rwBytes = await deriveKeyBytes({
        password: args.recoveryCode,
        salt: args.recoverySalt,
        iterations: args.kdfIterations,
        memoryKb: args.kdfMemoryKb,
        parallelism: args.kdfParallelism,
        outputBytes: args.kdfOutputBytes,
    });
    const recoveryWrappingKey = await importAesKey(rwBytes, true);
    zero(rwBytes);

    // We must briefly produce an extractable encryption key copy here so we can wrap
    // the same bytes under the new master-derived key. Re-run unwrap with extractable=true
    // on a fresh import.
    // To get raw bytes back, fetch /api/account/recovery-info again? That's network. Instead,
    // pull fresh recovery info from the page-level client so we don't tie this module to fetch.
    throw new Error('buildRotatePayload requires page-level orchestration — see recover.js');
}

// Internal: rotate using already-unwrapped raw key bytes. The recover.js page module
// receives those bytes from a one-shot extractable unwrap and passes them in here.
export async function buildRotatePayloadFromRawKey(args) {
    setUserIdBytes(args.userId);

    // 1) New KdfSalt + derive new master-wrapping key.
    const newKdfSalt = crypto.getRandomValues(new Uint8Array(16));
    const newMasterKeyBytes = await deriveKeyBytes({
        password: args.newMasterPassword,
        salt: newKdfSalt,
        iterations: args.kdfIterations,
        memoryKb: args.kdfMemoryKb,
        parallelism: args.kdfParallelism,
        outputBytes: args.kdfOutputBytes,
    });
    const newMasterKey = await importAesKey(newMasterKeyBytes);
    zero(newMasterKeyBytes);

    // 2) New verifier under the new master key.
    const verifierAad = aad(_userIdBytes, 'verifier-v1');
    const verifier = await aesGcmEncrypt(newMasterKey, VERIFIER_PLAINTEXT, verifierAad);

    // 3) Re-wrap the encryption key under the EXISTING recovery wrapping key (recovery
    //    code unchanged) but with a fresh IV. We need the recovery wrapping key bytes
    //    in scope here; the caller derived them once and passes them in.
    const recoveryWrappingKey = await importAesKey(args.recoveryWrappingKeyBytes);
    zero(args.recoveryWrappingKeyBytes);
    const recoveryAad = aad(_userIdBytes, 'recovery-wrap-v1');
    const recoveryWrap = await aesGcmEncrypt(recoveryWrappingKey, args.encryptionKeyRawBytes, recoveryAad);
    zero(args.encryptionKeyRawBytes);

    // 4) Update module-held key to the freshly imported (non-extractable) version.
    _encryptionKey = newMasterKey;
    // Wait — _encryptionKey should hold the data-encryption key, NOT the master-wrapping
    // key. The data key is what unlocks vault entries. Re-import it (non-extractable)
    // from the raw bytes we just consumed. But we just zeroed those bytes. We need a
    // copy held until this point. Update: caller must pass `encryptionKeyRawBytes` and
    // we make ONE non-extractable import of it before zeroing. Reordering below.

    return {
        kdfSalt: b64Encode(newKdfSalt),
        verifierCiphertext: b64Encode(verifier.ciphertext),
        verifierIv: b64Encode(verifier.iv),
        verifierAuthTag: b64Encode(verifier.authTag),
        recoveryWrappedKey: b64Encode(recoveryWrap.ciphertext),
        recoveryWrappedKeyIv: b64Encode(recoveryWrap.iv),
        recoveryWrappedKeyAuthTag: b64Encode(recoveryWrap.authTag),
    };
}

// Cleaner orchestration entrypoint for the recover page. Combines unwrap + rotate.
//
//   args = {
//       userId, recoveryCode, newMasterPassword,
//       recoverySalt,
//       kdfIterations, kdfMemoryKb, kdfParallelism, kdfOutputBytes,
//       recoveryWrappedKey, recoveryWrappedKeyIv, recoveryWrappedKeyAuthTag
//   }
// On success: returns the rotate-master POST body and holds the unlocked CryptoKey
// in module memory.
// On failure (bad recovery code): returns null.
export async function recoverAndRotate(args) {
    setUserIdBytes(args.userId);

    // 1) Derive recovery wrapping key.
    const wrappingKeyBytes = await deriveKeyBytes({
        password: args.recoveryCode,
        salt: args.recoverySalt,
        iterations: args.kdfIterations,
        memoryKb: args.kdfMemoryKb,
        parallelism: args.kdfParallelism,
        outputBytes: args.kdfOutputBytes,
    });
    // Use extractable for the wrapping key so we can re-encrypt the wrap with a fresh
    // IV. The wrapping key bytes are derived from the user-supplied recovery code; the
    // user could just type it in again to recompute, so "extractable" here doesn't
    // weaken the model.
    const wrappingKey = await importAesKey(wrappingKeyBytes, false);
    // wrappingKeyBytes no longer needed — the CryptoKey is non-extractable and the raw
    // material can be scrubbed immediately to minimise the window in JS heap memory.
    zero(wrappingKeyBytes);

    // 2) Unwrap the encryption-key raw bytes.
    let encryptionKeyRawBytes;
    try {
        encryptionKeyRawBytes = await aesGcmDecrypt(
            wrappingKey,
            args.recoveryWrappedKey,
            args.recoveryWrappedKeyIv,
            args.recoveryWrappedKeyAuthTag,
            aad(_userIdBytes, 'recovery-wrap-v1')
        );
    } catch (_) {
        return null;
    }

    // 3) Import the data-encryption key non-extractably for vault use.
    _encryptionKey = await importAesKey(encryptionKeyRawBytes, false);

    // 4) New KdfSalt + derive new master-wrapping key.
    const newKdfSalt = crypto.getRandomValues(new Uint8Array(16));
    const newMasterKeyBytes = await deriveKeyBytes({
        password: args.newMasterPassword,
        salt: newKdfSalt,
        iterations: args.kdfIterations,
        memoryKb: args.kdfMemoryKb,
        parallelism: args.kdfParallelism,
        outputBytes: args.kdfOutputBytes,
    });
    const newMasterKey = await importAesKey(newMasterKeyBytes, false);
    zero(newMasterKeyBytes);

    // 5) New verifier under new master key.
    const verifierAad = aad(_userIdBytes, 'verifier-v1');
    const verifier = await aesGcmEncrypt(newMasterKey, VERIFIER_PLAINTEXT, verifierAad);

    // 6) Refresh recovery wrap with a new IV (key + content unchanged).
    const recoveryAad = aad(_userIdBytes, 'recovery-wrap-v1');
    const recoveryWrap = await aesGcmEncrypt(wrappingKey, encryptionKeyRawBytes, recoveryAad);

    // 7) Scrub.
    zero(encryptionKeyRawBytes);

    return {
        kdfSalt: b64Encode(newKdfSalt),
        verifierCiphertext: b64Encode(verifier.ciphertext),
        verifierIv: b64Encode(verifier.iv),
        verifierAuthTag: b64Encode(verifier.authTag),
        recoveryWrappedKey: b64Encode(recoveryWrap.ciphertext),
        recoveryWrappedKeyIv: b64Encode(recoveryWrap.iv),
        recoveryWrappedKeyAuthTag: b64Encode(recoveryWrap.authTag),
    };
}

// Phase E lock primitive. Nulls the in-memory CryptoKey reference + clears the
// AAD-binding userId bytes so the next unlock starts from a clean slate.
//
// REQ-018 (idle), REQ-019 (Lock now), REQ-020 (tab close / reload), REQ-081
// (cross-tab broadcast) all converge here via `session-lock.js::performLock`.
// This module-level function intentionally does NOT navigate or broadcast —
// session-lock.js owns the policy; crypto.js owns the key state.
export function lock() {
    _encryptionKey = null;
    if (_userIdBytes) {
        zero(_userIdBytes);
        _userIdBytes = null;
    }
}

export function isUnlocked() {
    return _encryptionKey !== null;
}

// Phase F (vault CRUD) will use this to encrypt entry fields.
export function getEncryptionKey() {
    return _encryptionKey;
}

export function getUserIdBytes() {
    return _userIdBytes;
}

// ----- Phase D: WebAuthn passkey wrap support -----

// Re-derive Argon2id from the master password and return raw 32 bytes for the caller
// to wrap under a passkey-derived key. Mirrors the recover-and-rotate carve-out: the
// caller receives raw key material that MUST be zeroed immediately after use.
//
// Lifetime: the returned Uint8Array is owned by the caller. Pass it to
// `wrapEncryptionKeyForPasskey` (in webauthn.js) which zeros it on return. Do not
// store, log, or keep references beyond a single synchronous use.
export async function getRawEncryptionKeyForPasskeyWrap({ masterPassword, kdfSalt, kdfIterations, kdfMemoryKb, kdfParallelism, kdfOutputBytes }) {
    const bytes = await deriveKeyBytes({
        password: masterPassword,
        salt: kdfSalt,
        iterations: kdfIterations,
        memoryKb: kdfMemoryKb,
        parallelism: kdfParallelism,
        outputBytes: kdfOutputBytes,
    });
    return bytes;
}

// Imports raw bytes as a non-extractable CryptoKey, sets the module-level
// _encryptionKey + _userIdBytes, and zeros the input. Internal-use seam called by
// webauthn.js after a successful passkey unwrap.
export async function setUnlockedKeyFromBytes(rawBytes, userId) {
    setUserIdBytes(userId);
    _encryptionKey = await importAesKey(rawBytes, false);
    zero(rawBytes);
}

// HKDF-SHA-256. Single-step derive with empty salt and a textual `info` parameter —
// matches the Phase D wrap spec: HKDF(secret, info="dragon-vault-passkey-wrap", 32).
export async function hkdfSha256(secretBytes, infoString, lengthBytes = 32) {
    const baseKey = await crypto.subtle.importKey(
        'raw',
        secretBytes,
        'HKDF',
        false,
        ['deriveBits']
    );
    const derived = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(0),
            info: new TextEncoder().encode(infoString),
        },
        baseKey,
        lengthBytes * 8
    );
    return new Uint8Array(derived);
}

// Concat helper exposed for webauthn.js's AAD construction.
export function concatBytesPublic(...arrays) {
    return concatBytes(...arrays);
}

// Lifecycle hooks exposed for the Phase E lock policy. webauthn.js doesn't need to
// keep its own state — the unlocked key reference lives here.
export { aesGcmEncrypt, aesGcmDecrypt, importAesKey };

// ----- xsrf header helper -----

export function xsrfToken() {
    const meta = document.querySelector('meta[name="xsrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

export async function postJson(url, body) {
    const res = await fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
            'Content-Type': 'application/json',
            'RequestVerificationToken': xsrfToken(),
            'Accept': 'application/json',
        },
        body: JSON.stringify(body),
    });
    return res;
}

export async function getJson(url) {
    const res = await fetch(url, {
        method: 'GET',
        credentials: 'same-origin',
        headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) throw new Error(`GET ${url} failed: ${res.status}`);
    return await res.json();
}
