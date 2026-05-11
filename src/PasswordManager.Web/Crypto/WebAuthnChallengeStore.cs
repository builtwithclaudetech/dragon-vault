using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using PasswordManager.Core.Domain;
using PasswordManager.Core.Interfaces;
using PasswordManager.Data;

namespace PasswordManager.Web.Crypto;

// EF-backed implementation of the challenge store. 32-byte random challenges; rows are
// persisted with a 5-minute (configurable) expiry; ConsumeAsync stamps ConsumedUtc and
// is the only path that proves the challenge was used. Replay → ConsumedUtc is non-null
// on the row, so the predicate `ConsumedUtc IS NULL` makes the second consume miss the
// row entirely (returns false).
//
// Time source: DateTime.UtcNow. Keeping it simple; future hardening could inject
// TimeProvider — same TODO Phase B left for the audit interceptor.
internal sealed class WebAuthnChallengeStore : IWebAuthnChallengeStore
{
    private const int ChallengeBytes = 32;

    private readonly DragonVaultDbContext _db;
    private readonly Auth.DragonVaultFido2Options _config;

    public WebAuthnChallengeStore(DragonVaultDbContext db, Auth.DragonVaultFido2Options config)
    {
        _db = db;
        _config = config;
    }

    public async Task<byte[]> IssueAsync(Guid userId, string purpose, CancellationToken cancellationToken = default)
    {
        if (purpose is not ("register" or "assert"))
            throw new ArgumentException($"Invalid challenge purpose '{purpose}'", nameof(purpose));

        var challenge = RandomNumberGenerator.GetBytes(ChallengeBytes);
        var now = DateTime.UtcNow;
        _db.WebAuthnChallenges.Add(new WebAuthnChallenge
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Challenge = challenge,
            Purpose = purpose,
            CreatedUtc = now,
            ExpiresUtc = now.AddSeconds(_config.ChallengeTtlSeconds),
            ConsumedUtc = null,
        });
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return challenge;
    }

    public async Task<bool> ConsumeAsync(Guid userId, byte[] challenge, string purpose, CancellationToken cancellationToken = default)
    {
        if (challenge is null || challenge.Length == 0) return false;
        if (purpose is not ("register" or "assert")) return false;

        var now = DateTime.UtcNow;

        // Match user + purpose + non-consumed + not-expired, then byte-compare in memory
        // because EF Core can't translate SequenceEqual on byte[]. Race-safety is enforced
        // by the IsConcurrencyToken() on WebAuthnChallenge.ConsumedUtc (see configuration):
        // EF generates UPDATE ... WHERE Id = @id AND ConsumedUtc IS NULL, so a concurrent
        // caller that wins the race causes our SaveChangesAsync to affect 0 rows and throw
        // DbUpdateConcurrencyException, which we translate to a `false` return.
        var candidates = await _db.WebAuthnChallenges
            .Where(c => c.UserId == userId
                     && c.Purpose == purpose
                     && c.ConsumedUtc == null
                     && c.ExpiresUtc >= now)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        var match = candidates.FirstOrDefault(c => BytesEqual(c.Challenge, challenge));
        if (match is null) return false;

        match.ConsumedUtc = now;
        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (DbUpdateConcurrencyException)
        {
            // Concurrent caller already stamped ConsumedUtc — single-use contract holds.
            _db.Entry(match).State = EntityState.Detached;
            return false;
        }
    }

    // Constant-time-ish byte equality. Not strictly necessary here (the data is server-side
    // and we control what we issued) but cheap and good hygiene.
    private static bool BytesEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        var diff = 0;
        for (var i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
