namespace PasswordManager.Web.Models;

// Wire-format DTOs for the master-password setup, unlock, and recovery (rotate-master)
// flows. All binary blobs travel as base64-encoded strings; the controller decodes and
// validates lengths against design §3.1 column widths and §4 crypto parameters.
//
// Server-side invariants enforced on every payload:
//   - VerifierIv          = 12 bytes (AES-GCM nonce)
//   - VerifierAuthTag     = 16 bytes (AES-GCM tag)
//   - VerifierCiphertext  ≤ 256 bytes (column cap; current plaintext is 16 bytes)
//   - RecoveryWrappedKey* same shape (12 / 16 / ≤256)
//   - KdfSalt             = 16 bytes (REQ-013; the column is varbinary(32) for forward compat)
// Anything else gets a 400 Problem Details before it touches the DB.

public sealed record SetupRequest(
    string VerifierCiphertext,
    string VerifierIv,
    string VerifierAuthTag,
    string RecoveryWrappedKey,
    string RecoveryWrappedKeyIv,
    string RecoveryWrappedKeyAuthTag);

public sealed record RotateMasterRequest(
    string KdfSalt,
    string VerifierCiphertext,
    string VerifierIv,
    string VerifierAuthTag,
    string RecoveryWrappedKey,
    string RecoveryWrappedKeyIv,
    string RecoveryWrappedKeyAuthTag);

// Returned to the unlock page so the browser can derive the EncryptionKey and try the
// verifier blob. Contains nothing the server could itself use to recover plaintext —
// only KDF parameters, the per-user salt, and the AES-GCM verifier ciphertext.
public sealed record KdfInfoResponse(
    string KdfSalt,
    int KdfIterations,
    int KdfMemoryKb,
    int KdfParallelism,
    int KdfOutputBytes,
    string VerifierCiphertext,
    string VerifierIv,
    string VerifierAuthTag);

// Returned to the recovery page so the browser can derive the recovery wrapping key,
// unwrap the encryption key, and prompt for a new master password.
public sealed record RecoveryInfoResponse(
    string RecoverySalt,
    int KdfIterations,
    int KdfMemoryKb,
    int KdfParallelism,
    int KdfOutputBytes,
    string RecoveryWrappedKey,
    string RecoveryWrappedKeyIv,
    string RecoveryWrappedKeyAuthTag);
