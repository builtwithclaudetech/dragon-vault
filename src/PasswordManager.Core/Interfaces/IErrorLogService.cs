namespace PasswordManager.Core.Interfaces;

// a prior project-parity defensive logger (ADR-016). Implementations MUST swallow internal failures —
// callers should never have to defend against the logger throwing (REQ-058).
public interface IErrorLogService
{
    Task LogAsync(string source, string message, Exception? exception = null, CancellationToken cancellationToken = default);
}
