using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Skopka.Identity.Ef.Migrations
{
    /// <inheritdoc />
    public partial class PhoneScopes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ux_identity_login_identifiers_active_normalized_key",
                table: "identity_login_identifiers");

            migrationBuilder.DropIndex(
                name: "ux_auth_users_normalized_phone",
                table: "auth_users");

            migrationBuilder.AddColumn<string>(
                name: "phone_scope",
                table: "identity_login_identifiers",
                type: "TEXT",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "phone_scope",
                table: "auth_users",
                type: "TEXT",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "ux_identity_login_identifiers_active_normalized_key",
                table: "identity_login_identifiers",
                columns: new[] { "normalized_key", "phone_scope" },
                unique: true,
                filter: "is_active = 1");

            migrationBuilder.CreateIndex(
                name: "ux_auth_users_normalized_phone",
                table: "auth_users",
                columns: new[] { "normalized_phone", "phone_scope" },
                unique: true,
                filter: "deleted_at IS NULL AND normalized_phone IS NOT NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ux_identity_login_identifiers_active_normalized_key",
                table: "identity_login_identifiers");

            migrationBuilder.DropIndex(
                name: "ux_auth_users_normalized_phone",
                table: "auth_users");

            migrationBuilder.DropColumn(
                name: "phone_scope",
                table: "identity_login_identifiers");

            migrationBuilder.DropColumn(
                name: "phone_scope",
                table: "auth_users");

            migrationBuilder.CreateIndex(
                name: "ux_identity_login_identifiers_active_normalized_key",
                table: "identity_login_identifiers",
                column: "normalized_key",
                unique: true,
                filter: "is_active = 1");

            migrationBuilder.CreateIndex(
                name: "ux_auth_users_normalized_phone",
                table: "auth_users",
                column: "normalized_phone",
                unique: true,
                filter: "deleted_at IS NULL AND normalized_phone IS NOT NULL");
        }
    }
}
