namespace PasswordManager.Core.Domain;

public class EntryField
{
    public Guid Id { get; set; }
    public Guid EntryId { get; set; }

    // 'username' | 'password' | 'url' | 'notes' | 'totp_secret' | 'custom'
    public string FieldKind { get; set; } = "custom";

    // OQ-05: Plaintext custom-field key (max 256 chars). Only set for FieldKind == "custom".
    // Previously encrypted as KeyCiphertext/KeyIv/KeyAuthTag; now stored as plaintext
    // so users can search/filter by field name. Values remain encrypted.
    public string? Key { get; set; }

    public byte[] ValueCiphertext { get; set; } = [];
    public byte[] ValueIv { get; set; } = [];
    public byte[] ValueAuthTag { get; set; } = [];

    public int SortOrder { get; set; }
}
