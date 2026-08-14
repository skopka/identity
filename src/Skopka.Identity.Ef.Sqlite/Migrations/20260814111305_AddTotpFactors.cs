using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Skopka.Identity.Ef.Migrations
{
    /// <inheritdoc />
    public partial class AddTotpFactors : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "user_totp_factors",
                columns: table => new
                {
                    user_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    enrollment_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    protected_secret = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    state = table.Column<int>(type: "INTEGER", nullable: false),
                    last_accepted_counter = table.Column<long>(type: "INTEGER", nullable: true),
                    version = table.Column<long>(type: "INTEGER", nullable: false),
                    pending_expires_at = table.Column<long>(type: "INTEGER", nullable: true),
                    enabled_at = table.Column<long>(type: "INTEGER", nullable: true),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false),
                    modified_at = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_user_totp_factors", x => x.user_id);
                    table.ForeignKey(
                        name: "FK_user_totp_factors_auth_users_user_id",
                        column: x => x.user_id,
                        principalTable: "auth_users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "user_totp_recovery_codes",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    user_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    enrollment_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    code_hash = table.Column<string>(type: "TEXT", fixedLength: true, maxLength: 64, nullable: false),
                    version = table.Column<long>(type: "INTEGER", nullable: false),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false),
                    used_at = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_user_totp_recovery_codes", x => x.id);
                    table.ForeignKey(
                        name: "FK_user_totp_recovery_codes_user_totp_factors_user_id",
                        column: x => x.user_id,
                        principalTable: "user_totp_factors",
                        principalColumn: "user_id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ux_user_totp_factors_enrollment_id",
                table: "user_totp_factors",
                column: "enrollment_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ux_user_totp_recovery_codes_hash",
                table: "user_totp_recovery_codes",
                columns: new[] { "user_id", "enrollment_id", "code_hash" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "user_totp_recovery_codes");

            migrationBuilder.DropTable(
                name: "user_totp_factors");
        }
    }
}
