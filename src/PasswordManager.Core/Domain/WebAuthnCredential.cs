namespace PasswordManager.Core.Domain;

public class WebAuthnCredential
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }

    public byte[] CredentialId { get; set; } = [];
    public byte[] PublicKeyCose { get; set; } = [];
    public long SignCount { get; set; }
    public Guid? AaGuid { get; set; }
    public string? Transports { get; set; }
    public string? Nickname { get; set; }

    public byte[] WrappedKeyCiphertext { get; set; } = [];
    public byte[] WrappedKeyIv { get; set; } = [];
    public byte[] WrappedKeyAuthTag { get; set; } = [];

    // 'largeBlob' | 'prf'
    public string WrapMethod { get; set; } = "largeBlob";

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LastUsedUtc { get; set; }
}
