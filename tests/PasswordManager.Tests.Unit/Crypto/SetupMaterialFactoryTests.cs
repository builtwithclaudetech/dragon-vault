using FluentAssertions;
using PasswordManager.Web.Crypto;

namespace PasswordManager.Tests.Unit.Crypto;

// Coverage for the server-side material generator. Recovery code uses rejection
// sampling over a 62-char alphabet — we assert length, alphabet membership, and
// that consecutive calls produce distinct values (probabilistic — collision odds
// are 62^-32 ≈ 10^-57). Salt generators just check length and randomness.
public sealed class SetupMaterialFactoryTests
{
    [Fact]
    public void NewKdfSalt_Returns16Bytes()
    {
        var salt = SetupMaterialFactory.NewKdfSalt();
        salt.Should().HaveCount(16);
    }

    [Fact]
    public void NewRecoverySalt_Returns16Bytes()
    {
        var salt = SetupMaterialFactory.NewRecoverySalt();
        salt.Should().HaveCount(16);
    }

    [Fact]
    public void NewKdfSalt_ConsecutiveCalls_AreDifferent()
    {
        var a = SetupMaterialFactory.NewKdfSalt();
        var b = SetupMaterialFactory.NewKdfSalt();
        a.Should().NotEqual(b);
    }

    [Fact]
    public void NewRecoveryCode_Is32Chars()
    {
        var code = SetupMaterialFactory.NewRecoveryCode();
        code.Should().HaveLength(32);
    }

    [Fact]
    public void NewRecoveryCode_OnlyContainsAlphanumeric()
    {
        // Run several to amortize alphabet coverage. Each char must be in [A-Za-z0-9].
        for (var i = 0; i < 20; i++)
        {
            var code = SetupMaterialFactory.NewRecoveryCode();
            code.Should().MatchRegex("^[A-Za-z0-9]{32}$");
        }
    }

    [Fact]
    public void NewRecoveryCode_ConsecutiveCalls_AreDifferent()
    {
        var a = SetupMaterialFactory.NewRecoveryCode();
        var b = SetupMaterialFactory.NewRecoveryCode();
        a.Should().NotBe(b);
    }
}
