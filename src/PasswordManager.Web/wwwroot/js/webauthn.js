// Dragon Vault — WebAuthn passkey orchestration (Phase D, REQ-021..026).
//
// Two ceremonies live here:
//   - registerPasskey(): runs navigator.credentials.create + a follow-up get() to
//     write/read the wrap secret (largeBlob primary; prf fallback), then HKDF +
//     AES-GCM-wraps the encryption key under the passkey-derived key, then POSTs the
//     wrapped envelope + attestation to /api/webauthn/register/finish.
//   - unlockWithPasskey(): runs navigator.credentials.get with the per-credential
//     extension request, posts the assertion to /api/webauthn/assert/finish, receives
//     back the wrapped envelope, recomputes the wrap key from the extension result,
//     unwraps, imports as a non-extractable CryptoKey via crypto.js's
//     setUnlockedKeyFromBytes seam.
//
// Server NEVER sees the unwrapped EncryptionKey, the per-credential secret, or the
// wrapping key (REQ-073). All wrap/unwrap math runs in the browser.
//
// AAD scheme (design §4.3): `userId-utf8 || credentialId-bytes || "passkey-wrap-v1"`.
// Including the credentialId in the AAD prevents a row-swap attack — an attacker
// who corrupted the WebAuthnCredentials table to point one credential's wrap blob
// at another credential's row would fail the AES-GCM auth-tag check on unwrap.

import {
    b64Encode, b64Decode,
    b64uEncode, b64uDecode,
    hkdfSha256,
    setUnlockedKeyFromBytes,
    aesGcmEncrypt, aesGcmDecrypt, importAesKey,
    concatBytesPublic,
    postJson, getJson, xsrfToken,
} from '/js/crypto.js';

const HKDF_INFO = 'dragon-vault-passkey-wrap';
const AAD_LABEL = 'passkey-wrap-v1';

// Fixed PRF input — matches the server's sha256("dragon-vault-prf-input-v1") so the
// browser and server use the same 32-byte input every time. Reproducibility matters:
// PRF(input1) and PRF(input2) yield different secrets, so changing the input would
// invalidate every existing prf-wrapped credential.
const PRF_INPUT_V1 = (() => {
    // crypto.subtle.digest is async; precompute lazily on first use to keep this
    // module synchronous on import.
    let cached = null;
    return async () => {
        if (cached) return cached;
        const seed = new TextEncoder().encode('dragon-vault-prf-input-v1');
        const hash = await crypto.subtle.digest('SHA-256', seed);
        cached = new Uint8Array(hash);
        return cached;
    };
})();

function buildAad(userIdString, credentialIdBytes) {
    const userIdBytes = new TextEncoder().encode(userIdString);
    const labelBytes = new TextEncoder().encode(AAD_LABEL);
    return concatBytesPublic(userIdBytes, credentialIdBytes, labelBytes);
}

function zero(bytes) {
    if (bytes && bytes.fill) {
        try { bytes.fill(0); } catch (_) { /* frozen view */ }
    }
}

// Convert the begin-options JSON (challenge / id / rawId fields are base64url) into
// the BufferSource shape navigator.credentials APIs expect.
function decodeCreateOptions(options) {
    const out = JSON.parse(JSON.stringify(options));   // deep clone (still strings)
    out.challenge = b64uDecode(options.challenge);
    out.user.id = b64uDecode(options.user.id);
    if (Array.isArray(out.excludeCredentials)) {
        out.excludeCredentials = out.excludeCredentials.map(c => ({
            ...c,
            id: b64uDecode(c.id),
        }));
    }
    return out;
}

function decodeRequestOptions(options) {
    const out = JSON.parse(JSON.stringify(options));
    out.challenge = b64uDecode(options.challenge);
    if (Array.isArray(out.allowCredentials)) {
        out.allowCredentials = out.allowCredentials.map(c => ({
            ...c,
            id: b64uDecode(c.id),
        }));
    }
    // PRF eval.first travels as base64url → ArrayBuffer when present.
    if (out.extensions && out.extensions.prf && out.extensions.prf.eval) {
        const ev = out.extensions.prf.eval;
        if (typeof ev.first === 'string') ev.first = b64uDecode(ev.first);
    }
    return out;
}

// ArrayBuffer → Uint8Array (handles either input).
function asBytes(buf) {
    if (buf instanceof Uint8Array) return buf;
    if (buf instanceof ArrayBuffer) return new Uint8Array(buf);
    throw new TypeError('Expected ArrayBuffer or Uint8Array');
}

// Serialize a PublicKeyCredential (create or get response) to the WebAuthn-spec JSON
// shape that Fido2-Net-Lib parses on the server. Binary fields are base64url (the
// Fido2 deserializer accepts that for byte[] columns).
function serializeAttestationCredential(cred) {
    const att = cred.response;
    const transports = (att.getTransports && att.getTransports()) || undefined;
    return {
        id: cred.id,                                    // base64url already (DOM API)
        rawId: b64uEncode(asBytes(cred.rawId)),
        type: cred.type,
        response: {
            attestationObject: b64uEncode(asBytes(att.attestationObject)),
            clientDataJSON: b64uEncode(asBytes(att.clientDataJSON)),
            transports: transports,
        },
        // Server reads transports from response.transports above; extensions are
        // included for completeness but Fido2 doesn't enforce extension presence.
        extensions: {},
    };
}

function serializeAssertionCredential(cred) {
    const ar = cred.response;
    return {
        id: cred.id,
        rawId: b64uEncode(asBytes(cred.rawId)),
        type: cred.type,
        response: {
            authenticatorData: b64uEncode(asBytes(ar.authenticatorData)),
            clientDataJSON: b64uEncode(asBytes(ar.clientDataJSON)),
            signature: b64uEncode(asBytes(ar.signature)),
            userHandle: ar.userHandle ? b64uEncode(asBytes(ar.userHandle)) : null,
        },
        extensions: {},
    };
}

// ----- public API -----

// Registers a new passkey for the authenticated user. The browser is responsible for
// (a) running the create() ceremony, (b) acquiring a 32-byte wrap secret from the
// authenticator (largeBlob write OR prf eval), (c) HKDF + AES-GCM-wrapping the raw
// encryption key. The server only stores the wrapped ciphertext.
//
// args = { nickname, encryptionKeyRawBytes (Uint8Array, 32B, owned by caller), userId }
// On success: returns { id, wrapMethod }. The Uint8Array is zeroed before return.
export async function registerPasskey({ nickname, encryptionKeyRawBytes, userId }) {
    if (!encryptionKeyRawBytes || encryptionKeyRawBytes.length !== 32) {
        throw new Error('encryptionKeyRawBytes must be 32 bytes');
    }
    if (!('credentials' in navigator) || !navigator.credentials.create) {
        throw new Error('WebAuthn is not supported in this browser.');
    }

    // 1) /register/begin → CredentialCreationOptions JSON.
    const beginRes = await postJson('/api/webauthn/register/begin', {});
    if (!beginRes.ok) {
        zero(encryptionKeyRawBytes);
        throw new Error(`register/begin failed: ${beginRes.status}`);
    }
    const beginOptions = await beginRes.json();
    const publicKey = decodeCreateOptions(beginOptions);

    // 2) Create the credential.
    let cred;
    try {
        cred = await navigator.credentials.create({ publicKey });
    } catch (err) {
        zero(encryptionKeyRawBytes);
        throw err;
    }
    if (!cred) {
        zero(encryptionKeyRawBytes);
        throw new Error('navigator.credentials.create returned null');
    }

    const credIdBytes = asBytes(cred.rawId);

    // 3) Determine wrap method and acquire the secret.
    let wrapMethod;
    let secretBytes;

    const extResults = (cred.getClientExtensionResults && cred.getClientExtensionResults()) || {};

    if (extResults.largeBlob && extResults.largeBlob.supported === true) {
        // largeBlob write follow-up: a fresh 32B random secret.
        const fresh = crypto.getRandomValues(new Uint8Array(32));
        const writeOptions = {
            // Local-only write ceremony: the assertion produced by this get() is NEVER
            // sent to the server, so it does not need server-issued challenge freshness.
            // The credential was already attested in step 1; the only purpose of this
            // call is to prompt the authenticator to write `fresh` into largeBlob storage.
            // `writeResult.largeBlob.written === true` (checked below) is the only
            // confirmation we need — no replay-protection requirement applies.
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            allowCredentials: [{
                type: 'public-key',
                id: credIdBytes,
                transports: cred.response.getTransports ? cred.response.getTransports() : undefined,
            }],
            userVerification: 'preferred',
            extensions: { largeBlob: { write: fresh } },
            timeout: 60_000,
            rpId: publicKey.rp.id,
        };
        const writeAssertion = await navigator.credentials.get({ publicKey: writeOptions });
        const writeResult = writeAssertion.getClientExtensionResults && writeAssertion.getClientExtensionResults();
        if (!writeResult || !writeResult.largeBlob || writeResult.largeBlob.written !== true) {
            zero(encryptionKeyRawBytes);
            zero(fresh);
            throw new Error('Authenticator did not write largeBlob — passkey unlock unavailable for this device.');
        }
        wrapMethod = 'largeBlob';
        secretBytes = fresh;
    } else if (extResults.prf && extResults.prf.results && extResults.prf.results.first) {
        // Some authenticators evaluate prf during create() — use those bytes directly.
        wrapMethod = 'prf';
        secretBytes = asBytes(extResults.prf.results.first).slice();
    } else {
        // PRF fallback: do a follow-up get() with prf eval. Most common case for Windows
        // Hello / Android passkeys today. Same local-only-ceremony note as the largeBlob
        // write step: the assertion produced here is NEVER sent to the server, so a fresh
        // server-issued challenge is unnecessary — we only need the prf output to derive
        // the wrapping key. `prfRes.prf.results.first` (checked below) is the confirmation.
        const prfInput = await PRF_INPUT_V1();
        const prfOptions = {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            allowCredentials: [{
                type: 'public-key',
                id: credIdBytes,
                transports: cred.response.getTransports ? cred.response.getTransports() : undefined,
            }],
            userVerification: 'preferred',
            extensions: { prf: { eval: { first: prfInput } } },
            timeout: 60_000,
            rpId: publicKey.rp.id,
        };
        let prfAssertion;
        try {
            prfAssertion = await navigator.credentials.get({ publicKey: prfOptions });
        } catch (err) {
            zero(encryptionKeyRawBytes);
            throw new Error('This authenticator does not support largeBlob or prf — passkey unlock unavailable.');
        }
        const prfRes = prfAssertion.getClientExtensionResults && prfAssertion.getClientExtensionResults();
        if (!prfRes || !prfRes.prf || !prfRes.prf.results || !prfRes.prf.results.first) {
            zero(encryptionKeyRawBytes);
            throw new Error('This authenticator does not support largeBlob or prf — passkey unlock unavailable.');
        }
        wrapMethod = 'prf';
        secretBytes = asBytes(prfRes.prf.results.first).slice();
    }

    // 4) Derive wrap key + AES-GCM-wrap the encryption key.
    const wrapKeyBytes = await hkdfSha256(secretBytes, HKDF_INFO, 32);
    zero(secretBytes);

    const wrapKey = await importAesKey(wrapKeyBytes, false);
    zero(wrapKeyBytes);

    const aad = buildAad(userId, credIdBytes);
    const wrap = await aesGcmEncrypt(wrapKey, encryptionKeyRawBytes, aad);
    zero(encryptionKeyRawBytes);

    // 5) Hand attestation + wrap envelope to the server.
    const finishBody = {
        attestationResponse: serializeAttestationCredential(cred),
        wrappedKey: {
            ciphertext: b64Encode(wrap.ciphertext),
            iv: b64Encode(wrap.iv),
            authTag: b64Encode(wrap.authTag),
            wrapMethod,
        },
        nickname: nickname || null,
    };
    const finishRes = await postJson('/api/webauthn/register/finish', finishBody);
    if (!finishRes.ok) {
        const text = await finishRes.text();
        throw new Error(`register/finish failed: ${finishRes.status} ${text}`);
    }
    const result = await finishRes.json();
    return { id: result.id, wrapMethod };
}

// Unlock the vault using a passkey assertion. On success, the encryption key is held
// in crypto.js's module-scope as a non-extractable CryptoKey (REQ-017).
//
// args = { userId }
// Returns true on success, false on auth-tag mismatch (key bytes don't match).
export async function unlockWithPasskey({ userId }) {
    if (!('credentials' in navigator) || !navigator.credentials.get) {
        throw new Error('WebAuthn is not supported in this browser.');
    }

    // 1) /assert/begin → CredentialRequestOptions JSON.
    const beginRes = await postJson('/api/webauthn/assert/begin', {});
    if (!beginRes.ok) {
        throw new Error(`assert/begin failed: ${beginRes.status}`);
    }
    const beginOptions = await beginRes.json();
    const publicKey = decodeRequestOptions(beginOptions);

    // 2) Run the assertion.
    const assertion = await navigator.credentials.get({ publicKey });
    if (!assertion) throw new Error('navigator.credentials.get returned null');

    // 3) /assert/finish → server validates + returns wrappedKey.
    const finishBody = {
        assertionResponse: serializeAssertionCredential(assertion),
    };
    const finishRes = await postJson('/api/webauthn/assert/finish', finishBody);
    if (!finishRes.ok) {
        throw new Error(`assert/finish failed: ${finishRes.status}`);
    }
    const finishJson = await finishRes.json();

    // 4) Recover the per-credential secret from the extension results.
    const extResults = (assertion.getClientExtensionResults && assertion.getClientExtensionResults()) || {};
    let secretBytes;
    if (finishJson.wrappedKey.wrapMethod === 'largeBlob') {
        if (!extResults.largeBlob || !extResults.largeBlob.blob) {
            throw new Error('largeBlob blob missing from authenticator extension results.');
        }
        secretBytes = asBytes(extResults.largeBlob.blob).slice();
    } else if (finishJson.wrappedKey.wrapMethod === 'prf') {
        if (!extResults.prf || !extResults.prf.results || !extResults.prf.results.first) {
            throw new Error('prf result missing from authenticator extension results.');
        }
        secretBytes = asBytes(extResults.prf.results.first).slice();
    } else {
        throw new Error(`Unknown wrap method: ${finishJson.wrappedKey.wrapMethod}`);
    }

    // 5) Reconstruct wrap key + AES-GCM-decrypt the wrappedKey.
    const wrapKeyBytes = await hkdfSha256(secretBytes, HKDF_INFO, 32);
    zero(secretBytes);
    const wrapKey = await importAesKey(wrapKeyBytes, false);
    zero(wrapKeyBytes);

    const credIdBytes = b64Decode(finishJson.credentialId);
    const aad = buildAad(userId, credIdBytes);

    let rawKeyBytes;
    try {
        rawKeyBytes = await aesGcmDecrypt(
            wrapKey,
            b64Decode(finishJson.wrappedKey.ciphertext),
            b64Decode(finishJson.wrappedKey.iv),
            b64Decode(finishJson.wrappedKey.authTag),
            aad
        );
    } catch (_) {
        return false;   // auth tag mismatch — server-validated assertion but wrong wrap data
    }

    // 6) Hand the raw bytes to crypto.js for non-extractable import + zeroing.
    // Bridge the key across page navigation via sessionStorage (same pattern as
    // master-password unlock in Unlock.cshtml).
    sessionStorage.setItem('dv-unlock-key', JSON.stringify({
        rawKeyB64: btoa(String.fromCharCode(...rawKeyBytes)),
        userId: userId,
    }));
    await setUnlockedKeyFromBytes(rawKeyBytes, userId);
    return true;
}

// GET /api/webauthn/credentials → JSON array of summaries.
export async function listCredentials() {
    return await getJson('/api/webauthn/credentials');
}

// DELETE /api/webauthn/credentials/{id} — anti-forgery header attached.
export async function revokeCredential(id) {
    const res = await fetch(`/api/webauthn/credentials/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        credentials: 'same-origin',
        headers: { 'RequestVerificationToken': xsrfToken() },
    });
    if (!res.ok && res.status !== 204) {
        throw new Error(`revoke failed: ${res.status}`);
    }
}
