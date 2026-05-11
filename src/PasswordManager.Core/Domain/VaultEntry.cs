namespace PasswordManager.Core.Domain;

public class VaultEntry
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }

    public byte[] NameCiphertext { get; set; } = [];
    public byte[] NameIv { get; set; } = [];
    public byte[] NameAuthTag { get; set; } = [];

    public byte[]? TagsCiphertext { get; set; }
    public byte[]? TagsIv { get; set; }
    public byte[]? TagsAuthTag { get; set; }

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedUtc { get; set; } = DateTime.UtcNow;
    public Guid? CreatedBy { get; set; }
    public Guid? ModifiedBy { get; set; }

    /// <summary>
    /// Indicates whether tags have been normalized to lowercase by the client.
    /// Set to true on next client-side edit after tag-normalize JS is deployed.
    /// This is a bit column (NOT NULL, default 0) — the DB cannot normalize
    /// encrypted tags directly.
    /// </summary>
    public bool TagsNormalized { get; set; }

    // OQ-04: JSON column storing previous password entries as
    // [{ciphertext, iv, tag, changedUtc}, ...] (last 5, encrypted same AES-GCM as password).
    // Server is a dumb relay — never decrypts or inspects the contents.
    public string? PasswordHistoryJson { get; set; }

    public byte[] RowVersion { get; set; } = [];

    public ICollection<EntryField> Fields { get; set; } = new List<EntryField>();
}
