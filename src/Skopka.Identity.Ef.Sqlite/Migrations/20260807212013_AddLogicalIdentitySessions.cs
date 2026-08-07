using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Skopka.Identity.Ef.Migrations
{
    /// <inheritdoc />
    public partial class AddLogicalIdentitySessions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_identity_refresh_sessions_auth_users_user_id",
                table: "identity_refresh_sessions");

            migrationBuilder.DropIndex(
                name: "ix_identity_refresh_sessions_expires_at",
                table: "identity_refresh_sessions");

            migrationBuilder.DropIndex(
                name: "ix_identity_refresh_sessions_user_id",
                table: "identity_refresh_sessions");

            migrationBuilder.CreateTable(
                name: "identity_sessions",
                columns: table => new
                {
                    session_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    user_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    security_stamp = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    client_name = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    device_name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    version = table.Column<long>(type: "INTEGER", nullable: false),
                    expires_at = table.Column<long>(type: "INTEGER", nullable: false),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false),
                    last_refreshed_at = table.Column<long>(type: "INTEGER", nullable: false),
                    revoked_at = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_identity_sessions", x => x.session_id);
                    table.ForeignKey(
                        name: "FK_identity_sessions_auth_users_user_id",
                        column: x => x.user_id,
                        principalTable: "auth_users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.Sql(
                """
                INSERT INTO identity_sessions (
                    session_id,
                    user_id,
                    security_stamp,
                    client_name,
                    device_name,
                    version,
                    expires_at,
                    created_at,
                    last_refreshed_at,
                    revoked_at)
                SELECT
                    session_id,
                    MIN(user_id),
                    MIN(security_stamp),
                    MIN(client_name),
                    MIN(device_name),
                    1,
                    MAX(expires_at),
                    MIN(created_at),
                    MAX(created_at),
                    CASE
                        WHEN SUM(CASE WHEN revoked_at IS NULL THEN 1 ELSE 0 END) > 0
                            THEN NULL
                        ELSE MAX(revoked_at)
                    END
                FROM identity_refresh_sessions
                GROUP BY session_id;
                """);

            migrationBuilder.DropColumn(
                name: "client_name",
                table: "identity_refresh_sessions");

            migrationBuilder.DropColumn(
                name: "device_name",
                table: "identity_refresh_sessions");

            migrationBuilder.DropColumn(
                name: "expires_at",
                table: "identity_refresh_sessions");

            migrationBuilder.DropColumn(
                name: "revoked_at",
                table: "identity_refresh_sessions");

            migrationBuilder.DropColumn(
                name: "security_stamp",
                table: "identity_refresh_sessions");

            migrationBuilder.DropColumn(
                name: "user_id",
                table: "identity_refresh_sessions");

            migrationBuilder.CreateIndex(
                name: "ix_identity_sessions_expires_at",
                table: "identity_sessions",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "ix_identity_sessions_user_id",
                table: "identity_sessions",
                column: "user_id");

            migrationBuilder.AddForeignKey(
                name: "FK_identity_refresh_sessions_identity_sessions_session_id",
                table: "identity_refresh_sessions",
                column: "session_id",
                principalTable: "identity_sessions",
                principalColumn: "session_id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_identity_refresh_sessions_identity_sessions_session_id",
                table: "identity_refresh_sessions");

            migrationBuilder.AddColumn<string>(
                name: "client_name",
                table: "identity_refresh_sessions",
                type: "TEXT",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "device_name",
                table: "identity_refresh_sessions",
                type: "TEXT",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "expires_at",
                table: "identity_refresh_sessions",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<long>(
                name: "revoked_at",
                table: "identity_refresh_sessions",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "security_stamp",
                table: "identity_refresh_sessions",
                type: "TEXT",
                maxLength: 64,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<Guid>(
                name: "user_id",
                table: "identity_refresh_sessions",
                type: "TEXT",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.Sql(
                """
                UPDATE identity_refresh_sessions
                SET
                    user_id = (
                        SELECT user_id FROM identity_sessions
                        WHERE identity_sessions.session_id = identity_refresh_sessions.session_id),
                    security_stamp = (
                        SELECT security_stamp FROM identity_sessions
                        WHERE identity_sessions.session_id = identity_refresh_sessions.session_id),
                    client_name = (
                        SELECT client_name FROM identity_sessions
                        WHERE identity_sessions.session_id = identity_refresh_sessions.session_id),
                    device_name = (
                        SELECT device_name FROM identity_sessions
                        WHERE identity_sessions.session_id = identity_refresh_sessions.session_id),
                    expires_at = (
                        SELECT expires_at FROM identity_sessions
                        WHERE identity_sessions.session_id = identity_refresh_sessions.session_id),
                    revoked_at = (
                        SELECT revoked_at FROM identity_sessions
                        WHERE identity_sessions.session_id = identity_refresh_sessions.session_id);
                """);

            migrationBuilder.DropTable(
                name: "identity_sessions");

            migrationBuilder.CreateIndex(
                name: "ix_identity_refresh_sessions_expires_at",
                table: "identity_refresh_sessions",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "ix_identity_refresh_sessions_user_id",
                table: "identity_refresh_sessions",
                column: "user_id");

            migrationBuilder.AddForeignKey(
                name: "FK_identity_refresh_sessions_auth_users_user_id",
                table: "identity_refresh_sessions",
                column: "user_id",
                principalTable: "auth_users",
                principalColumn: "id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
