namespace PasswordManager.Core.Domain;

public class ErrorLogEntry
{
    public long Id { get; set; }
    public Guid? UserId { get; set; }
    public string Source { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string? Detail { get; set; }
    public string? StackTrace { get; set; }
    public string? RequestPath { get; set; }
    public DateTime OccurredUtc { get; set; } = DateTime.UtcNow;
}
