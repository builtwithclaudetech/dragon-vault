using System.Text.Json.Nodes;

namespace PasswordManager.Web.Models;

// Wire-format DTOs for the six WebAuthn endpoints under /api/webauthn.
//
// The browser exchanges three kinds of data with us:
//   1. WebAuthn ceremony JSON (CredentialCreateOptions / PublicKeyCredential / etc.) —
//      passed through as JsonNode so we don't have to re-model the entire WebAuthn JSON
//      spec. Server validates the meaningful parts via Fido2.MakeNewCredentialAsync /
//      MakeAssertionAsync.
//   2. The wrapped-key envelope — server-opaque ciphertext that the browser computed
//      from the passkey-derived secret. Travels as base64 strings; column-width caps
//      mirror AccountApiController's verifier-blob lengths (§3.1).
//   3. Display metadata (nickname, transports, timestamps) for the credentials list.

public sealed record WebAuthnWrappedKey(
    string Ciphertext,   // base64
    string Iv,           // base64, 12 bytes
    string AuthTag,      // base64, 16 bytes
    string WrapMethod);  // "largeBlob" | "prf"

// POST /api/webauthn/register/begin — empty body. We could take a nickname hint here,
// but the browser only finalizes the nickname at register/finish (after the user
// successfully completes the ceremony). Keeping begin payload-free avoids the partial-
// state question entirely.

// POST /api/webauthn/register/finish.
//
// AttestationResponse is the browser-supplied JSON of `navigator.credentials.create()`
// after the standard PublicKeyCredential -> JSON shape. Fido2-Net-Lib parses this via
// its own JSON contract; we forward it byte-for-byte.
public sealed record WebAuthnRegisterFinishRequest(
    JsonNode AttestationResponse,
    WebAuthnWrappedKey WrappedKey,
    string? Nickname);

// GET /api/webauthn/credentials response item.
public sealed record WebAuthnCredentialSummary(
    Guid Id,
    string? Nickname,
    string WrapMethod,
    string? Transports,
    DateTime CreatedUtc,
    DateTime? LastUsedUtc);

// POST /api/webauthn/assert/begin — optional preselect of a specific credential.
public sealed record WebAuthnAssertBeginRequest(string? CredentialId);

// POST /api/webauthn/assert/finish.
public sealed record WebAuthnAssertFinishRequest(JsonNode AssertionResponse);

// Response shape for assert/finish — the server-validated assertion hands back the
// stored wrapped key for the credential that authenticated. CredentialId is included
// so the client can derive the AAD that bound the wrap (userId || credentialId || label).
public sealed record WebAuthnAssertFinishResponse(
    string CredentialId,             // base64
    WebAuthnWrappedKey WrappedKey);
