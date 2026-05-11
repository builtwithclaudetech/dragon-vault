namespace PasswordManager.Core.Domain;

public class WebAuthnChallenge
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public byte[] Challenge { get; set; } = [];

    // 'register' | 'assert'
    public string Purpose { get; set; } = "assert";

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresUtc { get; set; }
    public DateTime? ConsumedUtc { get; set; }
}
