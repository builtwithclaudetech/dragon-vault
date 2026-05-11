namespace PasswordManager.Core.Interfaces;

// Resolves the authenticated user id at the moment of a SaveChanges call.
// Implementations live in the Web project (HttpContext-backed); Core stays free of
// ASP.NET Core dependencies.
public interface ICurrentUserAccessor
{
    Guid? GetCurrentUserId();
}
