using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Moq;
using PasswordManager.Core.Interfaces;
using PasswordManager.Web.Auth;

namespace PasswordManager.Tests.Unit.Auth;

// HttpContextCurrentUserAccessor is `internal sealed` in PasswordManager.Web; the Web project
// grants InternalsVisibleTo to this test assembly so we construct the type directly. All
// assertions exercise the public ICurrentUserAccessor contract.
public sealed class HttpContextCurrentUserAccessorTests
{
    private static ICurrentUserAccessor Create(IHttpContextAccessor accessor) =>
        new HttpContextCurrentUserAccessor(accessor);

    [Fact]
    public void GetCurrentUserId_NullHttpContext_ReturnsNull()
    {
        var accessorMock = new Mock<IHttpContextAccessor>();
        accessorMock.SetupGet(a => a.HttpContext).Returns((HttpContext?)null);

        var sut = Create(accessorMock.Object);

        var result = sut.GetCurrentUserId();

        result.Should().BeNull();
    }

    [Fact]
    public void GetCurrentUserId_UnauthenticatedUser_ReturnsNull()
    {
        var ctx = new DefaultHttpContext
        {
            // Default ClaimsPrincipal with no claims and no authentication type — FindFirstValue
            // still returns null, so the parse falls through and we get null.
            User = new ClaimsPrincipal(new ClaimsIdentity()),
        };
        var accessorMock = new Mock<IHttpContextAccessor>();
        accessorMock.SetupGet(a => a.HttpContext).Returns(ctx);

        var sut = Create(accessorMock.Object);

        var result = sut.GetCurrentUserId();

        result.Should().BeNull();
    }

    [Fact]
    public void GetCurrentUserId_NameIdentifierClaimMissing_ReturnsNull()
    {
        // Authenticated principal but lacking NameIdentifier — should still resolve to null
        // rather than throw. Common when a custom auth handler omits the sub claim.
        var identity = new ClaimsIdentity(authenticationType: "TestScheme");
        identity.AddClaim(new Claim(ClaimTypes.Email, "phil@example.com"));
        var ctx = new DefaultHttpContext { User = new ClaimsPrincipal(identity) };
        var accessorMock = new Mock<IHttpContextAccessor>();
        accessorMock.SetupGet(a => a.HttpContext).Returns(ctx);

        var sut = Create(accessorMock.Object);

        var result = sut.GetCurrentUserId();

        result.Should().BeNull();
    }

    [Theory]
    [InlineData("not-a-guid")]
    [InlineData("")]
    [InlineData("12345")]
    public void GetCurrentUserId_NameIdentifierNotParsableGuid_ReturnsNull(string raw)
    {
        var identity = new ClaimsIdentity(authenticationType: "TestScheme");
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, raw));
        var ctx = new DefaultHttpContext { User = new ClaimsPrincipal(identity) };
        var accessorMock = new Mock<IHttpContextAccessor>();
        accessorMock.SetupGet(a => a.HttpContext).Returns(ctx);

        var sut = Create(accessorMock.Object);

        var result = sut.GetCurrentUserId();

        result.Should().BeNull();
    }

    [Fact]
    public void GetCurrentUserId_ValidGuidClaim_ReturnsParsedGuid()
    {
        var expected = Guid.Parse("0F8FAD5B-D9CB-469F-A165-70867728950E");
        var identity = new ClaimsIdentity(authenticationType: "TestScheme");
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, expected.ToString()));
        var ctx = new DefaultHttpContext { User = new ClaimsPrincipal(identity) };
        var accessorMock = new Mock<IHttpContextAccessor>();
        accessorMock.SetupGet(a => a.HttpContext).Returns(ctx);

        var sut = Create(accessorMock.Object);

        var result = sut.GetCurrentUserId();

        result.Should().Be(expected);
    }
}
