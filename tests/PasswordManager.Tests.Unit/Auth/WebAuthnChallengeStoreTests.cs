using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using PasswordManager.Core.Domain;
using PasswordManager.Data;
using PasswordManager.Web.Auth;
using PasswordManager.Web.Crypto;

namespace PasswordManager.Tests.Unit.Auth;

// REQ-025 coverage. Issuing produces 32-byte challenges, persists a row with the right
// purpose and expiry; consuming is single-use, time-bounded, purpose-bound, user-bound.
public sealed class WebAuthnChallengeStoreTests : IDisposable
{
    private readonly DbContextOptions<DragonVaultDbContext> _options;
    private readonly DragonVaultDbContext _db;
    private readonly DragonVaultFido2Options _config = new()
    {
        RpId = "localhost",
        RpName = "Dragon Vault Tests",
        Origins = ["https://localhost:5001"],
        ChallengeTtlSeconds = 300,
    };

    public WebAuthnChallengeStoreTests()
    {
        _options = new DbContextOptionsBuilder<DragonVaultDbContext>()
            .UseInMemoryDatabase($"webauthn-challenges-{Guid.NewGuid()}")
            .Options;
        _db = new DragonVaultDbContext(_options);
    }

    public void Dispose()
    {
        _db.Dispose();
        GC.SuppressFinalize(this);
    }

    private WebAuthnChallengeStore CreateStore() => new(_db, _config);

    [Fact]
    public async Task Issue_Then_Consume_HappyPath_Returns_True_Once()
    {
        var store = CreateStore();
        var userId = Guid.NewGuid();

        var challenge = await store.IssueAsync(userId, "register");
        challenge.Should().HaveCount(32);

        var first = await store.ConsumeAsync(userId, challenge, "register");
        first.Should().BeTrue();

        // Second consume of the same challenge MUST fail (single-use).
        var second = await store.ConsumeAsync(userId, challenge, "register");
        second.Should().BeFalse();
    }

    [Fact]
    public async Task Consume_RejectsCrossPurpose()
    {
        var store = CreateStore();
        var userId = Guid.NewGuid();

        var challenge = await store.IssueAsync(userId, "register");
        var crossPurpose = await store.ConsumeAsync(userId, challenge, "assert");
        crossPurpose.Should().BeFalse();
    }

    [Fact]
    public async Task Consume_RejectsCrossUser()
    {
        var store = CreateStore();
        var userA = Guid.NewGuid();
        var userB = Guid.NewGuid();

        var challenge = await store.IssueAsync(userA, "assert");
        var crossUser = await store.ConsumeAsync(userB, challenge, "assert");
        crossUser.Should().BeFalse();
    }

    [Fact]
    public async Task Consume_RejectsExpiredChallenge()
    {
        var store = CreateStore();
        var userId = Guid.NewGuid();

        // Hand-write an expired row so we don't have to mess with TimeProvider.
        var expired = new WebAuthnChallenge
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Challenge = new byte[] { 1, 2, 3, 4, 5 },
            Purpose = "assert",
            CreatedUtc = DateTime.UtcNow.AddMinutes(-10),
            ExpiresUtc = DateTime.UtcNow.AddMinutes(-5),
            ConsumedUtc = null,
        };
        _db.WebAuthnChallenges.Add(expired);
        await _db.SaveChangesAsync();

        var ok = await store.ConsumeAsync(userId, expired.Challenge, "assert");
        ok.Should().BeFalse();
    }

    [Fact]
    public async Task Consume_NullOrEmptyChallenge_ReturnsFalse()
    {
        var store = CreateStore();
        var userId = Guid.NewGuid();

        (await store.ConsumeAsync(userId, [], "assert")).Should().BeFalse();
        (await store.ConsumeAsync(userId, null!, "assert")).Should().BeFalse();
    }

    [Fact]
    public async Task Issue_RejectsBogusPurpose()
    {
        var store = CreateStore();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            store.IssueAsync(Guid.NewGuid(), "delete"));
    }

    [Fact]
    public async Task Consume_StampsConsumedUtcOnSuccess()
    {
        var store = CreateStore();
        var userId = Guid.NewGuid();

        var challenge = await store.IssueAsync(userId, "register");
        var ok = await store.ConsumeAsync(userId, challenge, "register");
        ok.Should().BeTrue();

        var row = await _db.WebAuthnChallenges
            .FirstAsync(c => c.UserId == userId);
        row.ConsumedUtc.Should().NotBeNull();
    }
}
