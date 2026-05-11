using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PasswordManager.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddMasterPasswordVerifierBlob : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<byte[]>(
                name: "MasterPasswordVerifierBlob",
                table: "AspNetUsers",
                type: "varbinary(256)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "MasterPasswordVerifierBlob",
                table: "AspNetUsers");
        }
    }
}
