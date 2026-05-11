using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PasswordManager.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddTagsNormalizedColumn : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "TagsNormalized",
                table: "VaultEntries",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "TagsNormalized",
                table: "VaultEntries");
        }
    }
}
