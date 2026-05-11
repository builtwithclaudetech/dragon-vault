namespace PasswordManager.Web.Models;

// Wire-format DTOs for /api/vault/entries CRUD. Every binary blob travels as standard
// base64 (NOT base64url — Phase C/D set the precedent on standard for app-internal
// envelopes; only the WebAuthn ceremony JSON uses base64url because the spec mandates it).
//
// Server-side invariants enforced by VaultApiController:
//   - Every CipherBlobDto field is non-null/non-empty + valid base64.
//   - FieldKind ∈ { username, password, url, notes, totp_secret, custom }.
//   - Custom fields require a non-null plaintext Key string; well-known kinds require Key == null.
//   - Entry Id is client-generated so the browser can bake it into the AAD before round-
//     tripping through the server. Server rejects duplicate Ids with 409.
//   - OQ-05: Key is now a plaintext string (nvarchar), not encrypted ciphertext.

public sealed record CipherBlobDto(string Ciphertext, string Iv, string AuthTag);

public sealed record EntryFieldRequest(
    string FieldKind,
    string? Key,        // OQ-05: plaintext custom-field key (null for well-known kinds)
    CipherBlobDto Value,
    int SortOrder);

public sealed record CreateEntryRequest(
    Guid Id,
    CipherBlobDto Name,
    CipherBlobDto? Tags,
    IReadOnlyList<EntryFieldRequest> Fields);

public sealed record UpdateEntryRequest(
    CipherBlobDto Name,
    CipherBlobDto? Tags,
    IReadOnlyList<EntryFieldRequest> Fields,
    CipherBlobDto? PreviousPassword = null);  // OQ-04: encrypted previous password

public sealed record EntryFieldResponse(
    Guid Id,
    string FieldKind,
    string? Key,        // OQ-05: plaintext custom-field key (null for well-known kinds)
    CipherBlobDto Value,
    int SortOrder);

public sealed record EntryResponse(
    Guid Id,
    CipherBlobDto Name,
    CipherBlobDto? Tags,
    IReadOnlyList<EntryFieldResponse> Fields,
    string RowVersion,
    DateTime CreatedUtc,
    DateTime UpdatedUtc);
