using FluentAssertions;
using PasswordManager.Web.Auth;

namespace PasswordManager.Tests.Unit.Auth;

// REQ-002 / ADR-005: GoogleAuthOptions defaults are the single-user safety net. If config is
// missing or the binder hands back a freshly-constructed instance, the only person who can
// sign in is the maintainer. Lock that default in.
public sealed class GoogleAuthOptionsTests
{
    [Fact]
    public void Defaults_AllowedEmails_Containsthe maintainerOnly()
    {
        var sut = new GoogleAuthOptions();

        sut.AllowedEmails.Should().ContainSingle()
            .Which.Should().Be("user@example.com");
    }

    [Fact]
    public void Defaults_ClientCredentials_AreEmpty()
    {
        // Empty defaults force operators to provision real values via configuration; an
        // accidental "no config" run will fail at Google's side rather than silently use junk.
        var sut = new GoogleAuthOptions();

        sut.ClientId.Should().BeEmpty();
        sut.ClientSecret.Should().BeEmpty();
    }

    [Fact]
    public void SectionName_MatchesExpectedConfigurationPath()
    {
        // Constants tests are cheap insurance against accidental rename — design §14.3 pins
        // this to "Authentication:Google".
        GoogleAuthOptions.SectionName.Should().Be("Authentication:Google");
    }

    [Fact]
    public void AllowedEmails_AcceptsCustomList_ViaInitSetter()
    {
        // The binder produces a fresh record with AllowedEmails populated when configuration
        // supplies values; ensure the init setter actually replaces the default.
        var custom = new[] { "a@example.com", "b@example.com" };

        var sut = new GoogleAuthOptions { AllowedEmails = custom };

        sut.AllowedEmails.Should().BeEquivalentTo(custom);
    }
}
