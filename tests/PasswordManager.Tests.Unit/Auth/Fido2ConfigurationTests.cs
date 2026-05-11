using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PasswordManager.Web.Auth;

namespace PasswordManager.Tests.Unit.Auth;

// Coverage for the WebAuthn options binding and startup validation.
//
// ValidateOnStart (the production fail-fast path) fires via IStartupFilter during
// WebApplication.Build(), not during ServiceCollection.BuildServiceProvider(). The
// validator itself is tested directly here; integration-level tests validate the full
// startup path.
public sealed class Fido2ConfigurationTests
{
    [Fact]
    public void Bind_HappyPath_LoadsAllFields()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["WebAuthn:RpId"] = "pwm.example",
                ["WebAuthn:RpName"] = "Dragon Vault",
                ["WebAuthn:Origins:0"] = "https://pwm.example:8443",
                ["WebAuthn:Origins:1"] = "https://pwm.example",
                ["WebAuthn:ChallengeTtlSeconds"] = "120",
            })
            .Build();

        var bound = new DragonVaultFido2Options();
        config.GetSection(DragonVaultFido2Options.SectionName).Bind(bound);

        bound.RpId.Should().Be("pwm.example");
        bound.RpName.Should().Be("Dragon Vault");
        bound.Origins.Should().BeEquivalentTo("https://pwm.example:8443", "https://pwm.example");
        bound.ChallengeTtlSeconds.Should().Be(120);
    }

    [Fact]
    public void Bind_DefaultsApplyForOmittedFields()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["WebAuthn:RpId"] = "localhost",
                ["WebAuthn:Origins:0"] = "https://localhost:5001",
            })
            .Build();

        var bound = new DragonVaultFido2Options();
        config.GetSection(DragonVaultFido2Options.SectionName).Bind(bound);

        bound.RpName.Should().Be("Dragon Vault");      // POCO default
        bound.ChallengeTtlSeconds.Should().Be(300);    // POCO default = 5 min (REQ-025)
    }

    [Fact]
    public void Validator_Rejects_MissingRpId()
    {
        var options = new DragonVaultFido2Options
        {
            Origins = ["https://localhost"],
        };
        var validator = new WebAuthnOptionsValidation();
        var result = validator.Validate(Options.DefaultName, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("RpId");
    }

    [Fact]
    public void Validator_Rejects_EmptyOrigins()
    {
        var options = new DragonVaultFido2Options
        {
            RpId = "localhost",
            Origins = [],
        };
        var validator = new WebAuthnOptionsValidation();
        var result = validator.Validate(Options.DefaultName, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Origins");
    }

    [Fact]
    public void Validator_Accepts_ValidOptions()
    {
        var options = new DragonVaultFido2Options
        {
            RpId = "localhost",
            Origins = ["https://localhost:5001"],
        };
        var validator = new WebAuthnOptionsValidation();
        var result = validator.Validate(Options.DefaultName, options);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void BuildLibraryConfig_PopulatesFido2Config()
    {
        var options = new DragonVaultFido2Options
        {
            RpId = "pwm.example",
            RpName = "My Vault",
            Origins = ["https://pwm.example:8443"],
        };

        var fido2 = new Fido2NetLib.Fido2Configuration();
        DragonVaultFido2Options.BuildLibraryConfig(fido2, options);

        fido2.ServerDomain.Should().Be("pwm.example");
        fido2.ServerName.Should().Be("My Vault");
        fido2.Origins.Should().BeEquivalentTo("https://pwm.example:8443");
        fido2.TimestampDriftTolerance.Should().Be(300_000);
    }
}
