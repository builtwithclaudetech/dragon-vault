using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PasswordManager.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AspNetRoles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    NormalizedName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    ConcurrencyStamp = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetRoles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUsers",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    GoogleSubject = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    DisplayName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    KdfSalt = table.Column<byte[]>(type: "varbinary(32)", nullable: false),
                    KdfIterations = table.Column<int>(type: "int", nullable: false, defaultValue: 3),
                    KdfMemoryKb = table.Column<int>(type: "int", nullable: false, defaultValue: 65536),
                    KdfParallelism = table.Column<int>(type: "int", nullable: false, defaultValue: 4),
                    KdfOutputBytes = table.Column<int>(type: "int", nullable: false, defaultValue: 32),
                    VerifierCiphertext = table.Column<byte[]>(type: "varbinary(256)", nullable: false),
                    VerifierIv = table.Column<byte[]>(type: "varbinary(12)", nullable: false),
                    VerifierAuthTag = table.Column<byte[]>(type: "varbinary(16)", nullable: false),
                    RecoverySalt = table.Column<byte[]>(type: "varbinary(16)", nullable: false),
                    RecoveryWrappedKey = table.Column<byte[]>(type: "varbinary(256)", nullable: false),
                    RecoveryWrapIv = table.Column<byte[]>(type: "varbinary(12)", nullable: false),
                    RecoveryWrapAuthTag = table.Column<byte[]>(type: "varbinary(16)", nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2(3)", nullable: false, defaultValueSql: "SYSUTCDATETIME()"),
                    LastLoginUtc = table.Column<DateTime>(type: "datetime2(3)", nullable: true),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false),
                    UserName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    NormalizedUserName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    Email = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    NormalizedEmail = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    EmailConfirmed = table.Column<bool>(type: "bit", nullable: false),
                    PasswordHash = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SecurityStamp = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ConcurrencyStamp = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PhoneNumber = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PhoneNumberConfirmed = table.Column<bool>(type: "bit", nullable: false),
                    TwoFactorEnabled = table.Column<bool>(type: "bit", nullable: false),
                    LockoutEnd = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    LockoutEnabled = table.Column<bool>(type: "bit", nullable: false),
                    AccessFailedCount = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUsers", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ErrorLog",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Source = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    Message = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: false),
                    Detail = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    StackTrace = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    RequestPath = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    OccurredUtc = table.Column<DateTime>(type: "datetime2(3)", nullable: false, defaultValueSql: "SYSUTCDATETIME()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ErrorLog", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AspNetRoleClaims",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    RoleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ClaimType = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ClaimValue = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetRoleClaims", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AspNetRoleClaims_AspNetRoles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "AspNetRoles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserClaims",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ClaimType = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ClaimValue = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserClaims", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AspNetUserClaims_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserLogins",
                columns: table => new
                {
                    LoginProvider = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    ProviderKey = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    ProviderDisplayName = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserLogins", x => new { x.LoginProvider, x.ProviderKey });
                    table.ForeignKey(
                        name: "FK_AspNetUserLogins_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserRoles",
                columns: table => new
                {
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RoleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserRoles", x => new { x.UserId, x.RoleId });
                    table.ForeignKey(
                        name: "FK_AspNetUserRoles_AspNetRoles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "AspNetRoles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_AspNetUserRoles_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserTokens",
                columns: table => new
                {
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    LoginProvider = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Value = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserTokens", x => new { x.UserId, x.LoginProvider, x.Name });
                    table.ForeignKey(
                        name: "FK_AspNetUserTokens_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "VaultEntries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    NameCiphertext = table.Column<byte[]>(type: "varbinary(1024)", nullable: false),
                    NameIv = table.Column<byte[]>(type: "varbinary(12)", nullable: false),
                    NameAuthTag = table.Column<byte[]>(type: "varbinary(16)", nullable: false),
                    TagsCiphertext = table.Column<byte[]>(type: "varbinary(2048)", nullable: true),
                    TagsIv = table.Column<byte[]>(type: "varbinary(12)", nullable: true),
                    TagsAuthTag = table.Column<byte[]>(type: "varbinary(16)", nullable: true),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2(3)", nullable: false, defaultValueSql: "SYSUTCDATETIME()"),
                    UpdatedUtc = table.Column<DateTime>(type: "datetime2(3)", nullable: false, defaultValueSql: "SYSUTCDATETIME()"),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ModifiedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VaultEntries", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VaultEntries_Creator",
                        column: x => x.CreatedBy,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_VaultEntries_Modifier",
                        column: x => x.ModifiedBy,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_VaultEntries_Users",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "WebAuthnChallenges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Challenge = table.Column<byte[]>(type: "varbinary(64)", nullable: false),
                    Purpose = table.Column<string>(type: "varchar(16)", nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2(3)", nullable: false, defaultValueSql: "SYSUTCDATETIME()"),
                    ExpiresUtc = table.Column<DateTime>(type: "datetime2(3)", nullable: false),
                    ConsumedUtc = table.Column<DateTime>(type: "datetime2(3)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WebAuthnChallenges", x => x.Id);
                    table.CheckConstraint("CK_WebAuthnChallenges_Purpose", "[Purpose] IN ('register','assert')");
                    table.ForeignKey(
                        name: "FK_WebAuthnChallenges_Users",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "WebAuthnCredentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CredentialId = table.Column<byte[]>(type: "varbinary(512)", nullable: false),
                    PublicKeyCose = table.Column<byte[]>(type: "varbinary(1024)", nullable: false),
                    SignCount = table.Column<long>(type: "bigint", nullable: false, defaultValue: 0L),
                    AaGuid = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Transports = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    Nickname = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    WrappedKeyCiphertext = table.Column<byte[]>(type: "varbinary(256)", nullable: false),
                    WrappedKeyIv = table.Column<byte[]>(type: "varbinary(12)", nullable: false),
                    WrappedKeyAuthTag = table.Column<byte[]>(type: "varbinary(16)", nullable: false),
                    WrapMethod = table.Column<string>(type: "varchar(16)", nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2(3)", nullable: false, defaultValueSql: "SYSUTCDATETIME()"),
                    LastUsedUtc = table.Column<DateTime>(type: "datetime2(3)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WebAuthnCredentials", x => x.Id);
                    table.CheckConstraint("CK_WebAuthnCredentials_WrapMethod", "[WrapMethod] IN ('largeBlob','prf')");
                    table.ForeignKey(
                        name: "FK_WebAuthnCredentials_Users",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "EntryFields",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EntryId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    FieldKind = table.Column<string>(type: "varchar(16)", nullable: false),
                    KeyCiphertext = table.Column<byte[]>(type: "varbinary(512)", nullable: true),
                    KeyIv = table.Column<byte[]>(type: "varbinary(12)", nullable: true),
                    KeyAuthTag = table.Column<byte[]>(type: "varbinary(16)", nullable: true),
                    ValueCiphertext = table.Column<byte[]>(type: "varbinary(8000)", nullable: false),
                    ValueIv = table.Column<byte[]>(type: "varbinary(12)", nullable: false),
                    ValueAuthTag = table.Column<byte[]>(type: "varbinary(16)", nullable: false),
                    SortOrder = table.Column<int>(type: "int", nullable: false, defaultValue: 0)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EntryFields", x => x.Id);
                    table.CheckConstraint("CK_EntryFields_FieldKind", "[FieldKind] IN ('username','password','url','notes','totp_secret','custom')");
                    table.ForeignKey(
                        name: "FK_EntryFields_VaultEntries_EntryId",
                        column: x => x.EntryId,
                        principalTable: "VaultEntries",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AspNetRoleClaims_RoleId",
                table: "AspNetRoleClaims",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "RoleNameIndex",
                table: "AspNetRoles",
                column: "NormalizedName",
                unique: true,
                filter: "[NormalizedName] IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserClaims_UserId",
                table: "AspNetUserClaims",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserLogins_UserId",
                table: "AspNetUserLogins",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserRoles_RoleId",
                table: "AspNetUserRoles",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "EmailIndex",
                table: "AspNetUsers",
                column: "NormalizedEmail");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUsers_GoogleSubject",
                table: "AspNetUsers",
                column: "GoogleSubject",
                unique: true,
                filter: "[GoogleSubject] IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "UserNameIndex",
                table: "AspNetUsers",
                column: "NormalizedUserName",
                unique: true,
                filter: "[NormalizedUserName] IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_EntryFields_EntryId",
                table: "EntryFields",
                column: "EntryId");

            migrationBuilder.CreateIndex(
                name: "IX_ErrorLog_OccurredUtc",
                table: "ErrorLog",
                column: "OccurredUtc",
                descending: new bool[0]);

            migrationBuilder.CreateIndex(
                name: "IX_VaultEntries_CreatedBy",
                table: "VaultEntries",
                column: "CreatedBy");

            migrationBuilder.CreateIndex(
                name: "IX_VaultEntries_ModifiedBy",
                table: "VaultEntries",
                column: "ModifiedBy");

            migrationBuilder.CreateIndex(
                name: "IX_VaultEntries_UserId_UpdatedUtc",
                table: "VaultEntries",
                columns: new[] { "UserId", "UpdatedUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_WebAuthnChallenges_ExpiresUtc",
                table: "WebAuthnChallenges",
                column: "ExpiresUtc",
                filter: "[ConsumedUtc] IS NULL");

            migrationBuilder.CreateIndex(
                name: "IX_WebAuthnChallenges_UserId_ExpiresUtc",
                table: "WebAuthnChallenges",
                columns: new[] { "UserId", "ExpiresUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_WebAuthnCredentials_UserId",
                table: "WebAuthnCredentials",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "UQ_WebAuthnCredentials_CredentialId",
                table: "WebAuthnCredentials",
                column: "CredentialId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AspNetRoleClaims");

            migrationBuilder.DropTable(
                name: "AspNetUserClaims");

            migrationBuilder.DropTable(
                name: "AspNetUserLogins");

            migrationBuilder.DropTable(
                name: "AspNetUserRoles");

            migrationBuilder.DropTable(
                name: "AspNetUserTokens");

            migrationBuilder.DropTable(
                name: "EntryFields");

            migrationBuilder.DropTable(
                name: "ErrorLog");

            migrationBuilder.DropTable(
                name: "WebAuthnChallenges");

            migrationBuilder.DropTable(
                name: "WebAuthnCredentials");

            migrationBuilder.DropTable(
                name: "AspNetRoles");

            migrationBuilder.DropTable(
                name: "VaultEntries");

            migrationBuilder.DropTable(
                name: "AspNetUsers");
        }
    }
}
