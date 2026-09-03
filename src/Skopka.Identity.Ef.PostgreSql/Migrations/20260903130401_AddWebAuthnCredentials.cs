using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Skopka.Identity.Ef.Migrations
{
    /// <inheritdoc />
    public partial class AddWebAuthnCredentials : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "user_webauthn_credentials",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    credential_id = table.Column<byte[]>(type: "bytea", maxLength: 1023, nullable: false),
                    public_key = table.Column<byte[]>(type: "bytea", maxLength: 1024, nullable: false),
                    algorithm = table.Column<int>(type: "integer", nullable: false),
                    signature_counter = table.Column<long>(type: "bigint", nullable: false),
                    authenticator_id = table.Column<Guid>(type: "uuid", nullable: false),
                    backed_up = table.Column<bool>(type: "boolean", nullable: false),
                    label = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    version = table.Column<long>(type: "bigint", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_user_webauthn_credentials", x => x.id);
                    table.ForeignKey(
                        name: "FK_user_webauthn_credentials_auth_users_user_id",
                        column: x => x.user_id,
                        principalTable: "auth_users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_user_webauthn_credentials_user_id",
                table: "user_webauthn_credentials",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "ux_user_webauthn_credentials_credential_id",
                table: "user_webauthn_credentials",
                column: "credential_id",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "user_webauthn_credentials");
        }
    }
}
