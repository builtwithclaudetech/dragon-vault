using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PasswordManager.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddPasswordHistoryAndPlaintextKeys : Migration
    {
        // WARNING — breaking schema change (OQ-05):
        //   Drops KeyCiphertext / KeyIv / KeyAuthTag columns from EntryFields.
        //   Any existing encrypted custom-field key data in these columns is LOST.
        //   This is acceptable because there are no production users yet.
        //   Adds a new plaintext Key nvarchar(256) column for custom-field names.

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "KeyAuthTag",
                table: "EntryFields");

            migrationBuilder.DropColumn(
                name: "KeyCiphertext",
                table: "EntryFields");

            migrationBuilder.DropColumn(
                name: "KeyIv",
                table: "EntryFields");

            migrationBuilder.AddColumn<string>(
                name: "PasswordHistoryJson",
                table: "VaultEntries",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Key",
                table: "EntryFields",
                type: "nvarchar(256)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PasswordHistoryJson",
                table: "VaultEntries");

            migrationBuilder.DropColumn(
                name: "Key",
                table: "EntryFields");

            migrationBuilder.AddColumn<byte[]>(
                name: "KeyAuthTag",
                table: "EntryFields",
                type: "varbinary(16)",
                nullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "KeyCiphertext",
                table: "EntryFields",
                type: "varbinary(512)",
                nullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "KeyIv",
                table: "EntryFields",
                type: "varbinary(12)",
                nullable: true);
        }
    }
}
