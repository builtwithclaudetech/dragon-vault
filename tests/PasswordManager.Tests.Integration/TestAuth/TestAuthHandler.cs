using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace PasswordManager.Tests.Integration.TestAuth;

// Test-only authentication handler. Reads X-Test-User-Id header; if present and a valid
// Guid, mints an authenticated principal with that NameIdentifier so endpoint tests can
// hit [Authorize] routes without spinning up the Google OAuth pipeline.
//
// Registered with the Identity application scheme name so SignInManager / Identity-aware
// code sees a "real" Identity sign-in.
public sealed class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "TestAuth";
    public const string UserIdHeader = "X-Test-User-Id";

    public TestAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(UserIdHeader, out var rawId))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        if (!Guid.TryParse(rawId, out var id))
        {
            return Task.FromResult(AuthenticateResult.Fail("Invalid X-Test-User-Id header"));
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, id.ToString()),
            new Claim(ClaimTypes.Name, $"test-{id}"),
        };
        var identity = new ClaimsIdentity(claims, SchemeName);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
