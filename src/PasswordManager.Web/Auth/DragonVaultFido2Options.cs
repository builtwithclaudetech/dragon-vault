using Fido2NetLib;

namespace PasswordManager.Web.Auth;

// Bound from "WebAuthn" in appsettings.{Environment}.json (design §14.3).
//
// RpId is the host portion only (no port, no scheme — browsers strip them). For
// production this is "pwm.YOUR-SERVER-IP.nip.io"; locally it's "localhost".
//
// Origins is the full list of acceptable origin strings (scheme + host + port). Both
// the dev hosts (5001 / 7159) and the production binding (https://pwm.…:8443) belong
// here. WebAuthn assertion validation rejects assertions whose `origin` doesn't appear
// in this list.
//
// ChallengeTtlSeconds satisfies REQ-025: ≤ 5 minutes.
//
// Type name avoids `Fido2Configuration` because Fido2NetLib publishes a class of the
// same name; collision in any file `using`-ing both namespaces breaks compilation.
public sealed record DragonVaultFido2Options
{
    public const string SectionName = "WebAuthn";

    public string RpId { get; init; } = string.Empty;
    public string RpName { get; init; } = "Dragon Vault";
    public string[] Origins { get; init; } = [];
    public int ChallengeTtlSeconds { get; init; } = 300;

    // Extracted so the Fido2 library configuration can be unit-tested independently of the
    // DI container (Task 4.7). Populates a Fido2Configuration from the user-facing options.
    public static void BuildLibraryConfig(Fido2Configuration fido2, DragonVaultFido2Options options)
    {
        fido2.ServerDomain = options.RpId;
        fido2.ServerName = options.RpName;
        // Origins MUST include scheme + port for ceremony validation. WebAuthn spec
        // §13.4.9 requires case-sensitive origin matching, so we use Ordinal not
        // OrdinalIgnoreCase — a misconfigured `https://LOCALHOST:5001` should fail loudly
        // rather than silently match a real `https://localhost:5001` origin.
        fido2.Origins = new HashSet<string>(options.Origins, StringComparer.Ordinal);
        fido2.TimestampDriftTolerance = 300_000; // 5 min
    }
}
