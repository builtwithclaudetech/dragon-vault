using Microsoft.Extensions.Options;

namespace PasswordManager.Web.Auth;

// Startup validation for WebAuthn options (design §14.3). Binds appsettings { "WebAuthn": { ... } }
// through IOptions<DragonVaultFido2Options> with ValidateOnStart() so a missing RpId or empty
// Origins list fails-fast before the first request.
//
// Validates the same invariants the old AddDragonVaultFido2 threw on, but now via the
// framework's options validation pipeline instead of an ad-hoc throw at registration time.
public sealed class WebAuthnOptionsValidation : IValidateOptions<DragonVaultFido2Options>
{
    public ValidateOptionsResult Validate(string? name, DragonVaultFido2Options options)
    {
        if (string.IsNullOrWhiteSpace(options.RpId))
        {
            return ValidateOptionsResult.Fail(
                $"WebAuthn:RpId is missing. Configure '{DragonVaultFido2Options.SectionName}' in appsettings.{{Environment}}.json (design §14.3).");
        }

        if (options.Origins is null || options.Origins.Length == 0)
        {
            return ValidateOptionsResult.Fail(
                "WebAuthn:Origins must list at least one origin (e.g. https://{RpId}).");
        }

        return ValidateOptionsResult.Success;
    }
}
