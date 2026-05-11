using System.Net;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;

namespace PasswordManager.Tests.Integration;

// Endpoint coverage for Phase B auth surface: anonymous Login GET, error-banner mapping,
// challenge redirect-to-login on protected routes, and Google challenge issuance shape.
public sealed class AuthEndpointsTests : IClassFixture<DragonVaultWebApplicationFactory>
{
    private readonly DragonVaultWebApplicationFactory _factory;

    public AuthEndpointsTests(DragonVaultWebApplicationFactory factory)
    {
        _factory = factory;
    }

    private HttpClient CreateNonRedirectingClient() =>
        _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

    [Fact]
    public async Task Healthz_RoutesToProbe_AndReturnsKnownStatus()
    {
        // /healthz pings DragonVaultDbContext.Database.CanConnectAsync; under the EF Core
        // in-memory provider that call's behavior is not contractually `true` (the provider
        // has no real "connection" concept), so this test only asserts the route is wired up
        // and returns one of the documented codes (200 OK / 503 Service Unavailable).
        // A SQL Server-backed integration suite (Phase J / deployment smoke) covers the OK path.
        using var client = _factory.CreateClient();

        var response = await client.GetAsync(new Uri("/healthz", UriKind.Relative));

        response.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.ServiceUnavailable);
    }

    [Fact]
    public async Task Login_GET_Anonymous_Returns200_WithGoogleSignInLink()
    {
        using var client = _factory.CreateClient();

        var response = await client.GetAsync(new Uri("/Account/Login", UriKind.Relative));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("Sign in with Google");
    }

    [Theory]
    [InlineData("auth_failed", "Sign-in failed. Please try again.")]
    [InlineData("not_allowed", "This Google account is not authorized for Dragon Vault.")]
    public async Task Login_GET_WithErrorQuery_RendersBannerCopy(string errorCode, string expectedBanner)
    {
        using var client = _factory.CreateClient();

        var response = await client.GetAsync(
            new Uri($"/Account/Login?error={errorCode}", UriKind.Relative));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain(expectedBanner);
        body.Should().Contain($"data-error-code=\"{errorCode}\"");
    }

    [Fact]
    public async Task Login_GET_WithUnknownErrorCode_OmitsBanner()
    {
        // The view's switch returns null for unrecognized codes — no banner div should render.
        using var client = _factory.CreateClient();

        var response = await client.GetAsync(
            new Uri("/Account/Login?error=mystery_code", UriKind.Relative));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().NotContain("data-error-code=");
    }

    [Theory]
    [InlineData("/Vault/Unlock")]
    [InlineData("/Account/Setup")]
    public async Task ProtectedRoute_AnonymousUser_RedirectsToLogin(string path)
    {
        using var client = CreateNonRedirectingClient();

        var response = await client.GetAsync(new Uri(path, UriKind.Relative));

        response.StatusCode.Should().Be(HttpStatusCode.Found);
        response.Headers.Location.Should().NotBeNull();
        // Identity's challenge URL is "{scheme}://{host}/Account/Login?ReturnUrl=...". The
        // HttpsSchemeMiddleware (REQ-004) forces scheme=https, so the redirect arrives as an
        // absolute https URL — assert path + query rather than the absolute prefix.
        var location = response.Headers.Location!;
        var pathAndQuery = location.IsAbsoluteUri ? location.PathAndQuery : location.OriginalString;
        pathAndQuery.Should().StartWith("/Account/Login", "Identity's challenge should land on the Login page");
        pathAndQuery.Should().Contain("ReturnUrl");
    }

    [Fact]
    public async Task ExternalLogin_GET_Google_Redirects_ToAccountsGoogleCom_WithSignInGoogleCallback()
    {
        // Don't actually hit Google — the challenge redirects with a 302 whose Location is the
        // Google authorize URL. Assert host and that redirect_uri targets /signin-google.
        using var client = CreateNonRedirectingClient();

        var response = await client.GetAsync(
            new Uri("/Account/ExternalLogin", UriKind.Relative));

        response.StatusCode.Should().Be(HttpStatusCode.Found);
        var location = response.Headers.Location;
        location.Should().NotBeNull();
        location!.Host.Should().Be("accounts.google.com");

        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(location.Query);
        query.TryGetValue("redirect_uri", out var redirectUriValues).Should().BeTrue();
        var redirectUri = redirectUriValues.ToString();
        redirectUri.Should().NotBeNullOrEmpty();
        redirectUri.Should().EndWith("/signin-google");
    }
}
