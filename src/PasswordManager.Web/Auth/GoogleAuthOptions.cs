namespace PasswordManager.Web.Auth;

// Bound from "Authentication:Google" in appsettings.Development.json (design §14.3).
// AllowedEmails defaults to the single-user allowlist (REQ-002, ADR-005); the binder
// preserves the configured array if any value is supplied.
internal sealed record GoogleAuthOptions
{
    public const string SectionName = "Authentication:Google";

    public string ClientId { get; init; } = string.Empty;
    public string ClientSecret { get; init; } = string.Empty;
    public IReadOnlyList<string> AllowedEmails { get; init; } = ["user@example.com"];
}
