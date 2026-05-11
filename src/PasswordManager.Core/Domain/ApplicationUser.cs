using Microsoft.AspNetCore.Identity;

namespace PasswordManager.Core.Domain;

// Identity user augmented with Dragon Vault crypto material per design §3.1.
// Server stores only KDF parameters, salts, verifier blob, and the recovery-wrapped key —
// never the master password, recovery code, or encryption key in plaintext (REQ-073).
public class ApplicationUser : IdentityUser<Guid>
{
    public string? GoogleSubject { get; set; }
    public string? DisplayName { get; set; }

    public byte[] KdfSalt { get; set; } = [];
    public int KdfIterations { get; set; } = 3;
    public int KdfMemoryKb { get; set; } = 65536;
    public int KdfParallelism { get; set; } = 4;
    public int KdfOutputBytes { get; set; } = 32;

    public byte[] VerifierCiphertext { get; set; } = [];
    public byte[] VerifierIv { get; set; } = [];
    public byte[] VerifierAuthTag { get; set; } = [];

    public byte[] RecoverySalt { get; set; } = [];
    public byte[] RecoveryWrappedKey { get; set; } = [];
    public byte[] RecoveryWrapIv { get; set; } = [];
    public byte[] RecoveryWrapAuthTag { get; set; } = [];

    // Phase B addition (REQ-009 first-sign-in routing). Null until Phase C completes the
    // master-password setup flow and writes the verifier blob. Picked over a "no passkeys"
    // probe because Phase C sets up the master password BEFORE Phase D adds passkeys —
    // a passkey-count check would misroute the user back to Setup after first unlock.
    // Phase C will write to this; Phase B only branches on `is null`.
    public byte[]? MasterPasswordVerifierBlob { get; set; }

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginUtc { get; set; }

    public byte[] RowVersion { get; set; } = [];
}
