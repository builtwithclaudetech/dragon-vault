using Fido2NetLib;
using Microsoft.Extensions.Options;
using PasswordManager.Core.Interfaces;
using PasswordManager.Web.Crypto;

namespace PasswordManager.Web.Auth;

internal static class WebAuthnServiceExtensions
{
    // Registers Fido2-Net-Lib + the EF-backed challenge store + IOptions<DragonVaultFido2Options>
    // with startup validation (IValidateOptions + ValidateOnStart).
    //
    // Validation-on-start replaces the old ad-hoc throw-at-registration guard. The validator
    // checks RpId and Origins are non-empty before the first request is served.
    public static IServiceCollection AddDragonVaultFido2(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Wire IOptions<DragonVaultFido2Options> with binding + startup validation.
        services.AddOptions<DragonVaultFido2Options>()
            .Bind(configuration.GetSection(DragonVaultFido2Options.SectionName))
            .ValidateOnStart();

        services.AddSingleton<IValidateOptions<DragonVaultFido2Options>, WebAuthnOptionsValidation>();

        // Read the config immediately for Fido2 setup (AddFido2 lambda runs at registration
        // time, not at resolution time, so we cannot resolve IOptions<> from DI here).
        var fido2Options = configuration
            .GetSection(DragonVaultFido2Options.SectionName)
            .Get<DragonVaultFido2Options>() ?? new DragonVaultFido2Options();

        // Register the concrete type as a singleton. WebAuthnChallengeStore (and any other
        // consumer that pre-dates the IOptions<T> migration) resolves DragonVaultFido2Options
        // directly rather than through IOptions<T>. The IOptions<T> pipeline above carries
        // identical values since both bind from the same config section.
        services.AddSingleton(fido2Options);

        services.AddFido2(o => DragonVaultFido2Options.BuildLibraryConfig(o, fido2Options));

        services.AddScoped<IWebAuthnChallengeStore, WebAuthnChallengeStore>();
        return services;
    }
}
