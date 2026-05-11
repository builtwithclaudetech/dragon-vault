using System.Security.Claims;
using PasswordManager.Core.Interfaces;

namespace PasswordManager.Web.Auth;

// HttpContext-backed implementation of ICurrentUserAccessor. Resolves the authenticated
// user id from `ClaimTypes.NameIdentifier` on each call (NOT cached — a request may
// SignIn mid-flight, e.g. inside the OAuth OnTicketReceived handler).
internal sealed class HttpContextCurrentUserAccessor : ICurrentUserAccessor
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public HttpContextCurrentUserAccessor(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public Guid? GetCurrentUserId()
    {
        var raw = _httpContextAccessor.HttpContext?.User?.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(raw, out var id) ? id : null;
    }
}
