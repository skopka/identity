using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Skopka.Identity.Ef.Migrations
{
    /// <inheritdoc />
    public partial class AddExternalLoginLifecycleAndSessionMetadata : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_user_external_logins_auth_users_user_id",
                table: "user_external_logins");

            migrationBuilder.DropPrimaryKey(
                name: "PK_user_external_logins",
                table: "user_external_logins");

            migrationBuilder.RenameIndex(
                name: "IX_user_external_logins_user_id",
                table: "user_external_logins",
                newName: "ix_user_external_logins_user_id");

            migrationBuilder.AlterColumn<string>(
                name: "subject",
                table: "user_external_logins",
                type: "character varying(512)",
                maxLength: 512,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "text");

            migrationBuilder.AlterColumn<string>(
                name: "provider",
                table: "user_external_logins",
                type: "character varying(128)",
                maxLength: 128,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "text");

            migrationBuilder.AddColumn<string>(
                name: "client_name",
                table: "identity_refresh_sessions",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "device_name",
                table: "identity_refresh_sessions",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddPrimaryKey(
                name: "pk_user_external_logins",
                table: "user_external_logins",
                columns: new[] { "provider", "subject" });

            migrationBuilder.AddForeignKey(
                name: "fk_user_external_logins_auth_users_user_id",
                table: "user_external_logins",
                column: "user_id",
                principalTable: "auth_users",
                principalColumn: "id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "fk_user_external_logins_auth_users_user_id",
                table: "user_external_logins");

            migrationBuilder.DropPrimaryKey(
                name: "pk_user_external_logins",
                table: "user_external_logins");

            migrationBuilder.DropColumn(
                name: "client_name",
                table: "identity_refresh_sessions");

            migrationBuilder.DropColumn(
                name: "device_name",
                table: "identity_refresh_sessions");

            migrationBuilder.RenameIndex(
                name: "ix_user_external_logins_user_id",
                table: "user_external_logins",
                newName: "IX_user_external_logins_user_id");

            migrationBuilder.AlterColumn<string>(
                name: "subject",
                table: "user_external_logins",
                type: "text",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(512)",
                oldMaxLength: 512);

            migrationBuilder.AlterColumn<string>(
                name: "provider",
                table: "user_external_logins",
                type: "text",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(128)",
                oldMaxLength: 128);

            migrationBuilder.AddPrimaryKey(
                name: "PK_user_external_logins",
                table: "user_external_logins",
                columns: new[] { "provider", "subject" });

            migrationBuilder.AddForeignKey(
                name: "FK_user_external_logins_auth_users_user_id",
                table: "user_external_logins",
                column: "user_id",
                principalTable: "auth_users",
                principalColumn: "id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
