namespace PasswordManager.Core.Interfaces;

// Server-issued single-use challenges for WebAuthn ceremonies (REQ-025, design §3.1).
//
// Challenges MUST be:
//   - Single use (consumed exactly once; second consume returns false).
//   - Time-bounded (≤ 5 minutes per design §14.3 / REQ-025).
//   - Purpose-bound ("register" or "assert" — cross-purpose use rejected).
//   - User-bound (a challenge issued to user A cannot be redeemed by user B).
//
// Pruning of expired rows is REQ-077 / Phase L (background hosted service); this
// interface only owns the issue / consume contract.
public interface IWebAuthnChallengeStore
{
    Task<byte[]> IssueAsync(Guid userId, string purpose, CancellationToken cancellationToken = default);

    Task<bool> ConsumeAsync(Guid userId, byte[] challenge, string purpose, CancellationToken cancellationToken = default);
}
