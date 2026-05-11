using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;

namespace PasswordManager.Tests.Integration.TestAuth;

// Replaces IAntiforgery in the test host so [ValidateAntiForgeryToken] becomes a no-op.
// Production wiring (real token validation, header name, etc.) lives in Program.cs and
// is unchanged — anti-forgery semantics are exercised by manual / browser tests, not by
// these endpoint integration tests, which focus on payload validation + persistence.
internal sealed class NoOpAntiforgery : IAntiforgery
{
    public AntiforgeryTokenSet GetAndStoreTokens(HttpContext httpContext) =>
        new(requestToken: "test", cookieToken: "test", formFieldName: "__rvt", headerName: "RequestVerificationToken");

    public AntiforgeryTokenSet GetTokens(HttpContext httpContext) =>
        new(requestToken: "test", cookieToken: "test", formFieldName: "__rvt", headerName: "RequestVerificationToken");

    public Task<bool> IsRequestValidAsync(HttpContext httpContext) => Task.FromResult(true);

    public Task ValidateRequestAsync(HttpContext httpContext) => Task.CompletedTask;

    public void SetCookieTokenAndHeader(HttpContext httpContext) { }
}
