using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PasswordManager.Core.Domain;
using PasswordManager.Core.Interfaces;

namespace PasswordManager.Data.Services;

// Defensive a prior project-parity logger (REQ-057, REQ-058, ADR-016). Any failure inside this method
// MUST be swallowed so the calling controller can still return a controlled HTTP response.
// We resolve a fresh DbContext per call from a scope to avoid coupling to the request scope —
// log calls inside background services and middleware should not require an active scope.
public sealed class ErrorLogService : IErrorLogService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<ErrorLogService> _logger;

    public ErrorLogService(IServiceScopeFactory scopeFactory, ILogger<ErrorLogService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    public async Task LogAsync(string source, string message, Exception? exception = null, CancellationToken cancellationToken = default)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<DragonVaultDbContext>();

            var entry = new ErrorLogEntry
            {
                Source = Truncate(source, 256),
                Message = Truncate(message, 2048),
                Detail = exception?.Message,
                StackTrace = exception?.ToString(),
                OccurredUtc = DateTime.UtcNow
            };

            db.ErrorLog.Add(entry);
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Last-resort: write to ILogger so the bootstrap file sink captures it.
            // Never rethrow — caller relies on this never propagating.
            _logger.LogError(ex, "ErrorLogService.LogAsync failed for source={Source}", source);
        }
    }

    private static string Truncate(string value, int max) =>
        string.IsNullOrEmpty(value) ? string.Empty : value.Length <= max ? value : value[..max];
}
