using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;
using PasswordManager.Core.Domain;
using PasswordManager.Core.Interfaces;

namespace PasswordManager.Data;

// Stamps VaultEntry.UpdatedUtc, CreatedBy, and ModifiedBy automatically on insert/update so
// service-layer code never has to remember (design §3.2). The current user id is supplied
// by an injected ICurrentUserAccessor so this assembly stays free of HttpContext / ASP.NET
// dependencies. Registered as scoped (alongside DbContext) since the underlying accessor
// resolves HttpContext per request.
public sealed class AuditSaveChangesInterceptor : SaveChangesInterceptor
{
    private readonly ICurrentUserAccessor _currentUser;
    private readonly TimeProvider _timeProvider;

    public AuditSaveChangesInterceptor(ICurrentUserAccessor currentUser, TimeProvider? timeProvider = null)
    {
        _currentUser = currentUser;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
    {
        Stamp(eventData.Context);
        return base.SavingChanges(eventData, result);
    }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        Stamp(eventData.Context);
        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    private void Stamp(DbContext? ctx)
    {
        if (ctx is null) return;

        var userId = _currentUser.GetCurrentUserId();
        var now = _timeProvider.GetUtcNow().UtcDateTime;

        foreach (EntityEntry entry in ctx.ChangeTracker.Entries<VaultEntry>())
        {
            if (entry.State == EntityState.Added)
            {
                var e = (VaultEntry)entry.Entity;
                e.CreatedBy ??= userId;
                e.ModifiedBy = userId;
                e.UpdatedUtc = now;
            }
            else if (entry.State == EntityState.Modified)
            {
                var e = (VaultEntry)entry.Entity;
                e.ModifiedBy = userId;
                e.UpdatedUtc = now;
            }
        }
    }
}
