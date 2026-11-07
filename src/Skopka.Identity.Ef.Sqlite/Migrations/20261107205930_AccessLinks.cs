using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Skopka.Identity.Ef.Migrations
{
    /// <inheritdoc />
    public partial class AccessLinks : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "identity_access_links",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    user_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    user_version = table.Column<long>(type: "INTEGER", nullable: false),
                    scope = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    token_hash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    expires_at = table.Column<long>(type: "INTEGER", nullable: false),
                    version = table.Column<long>(type: "INTEGER", nullable: false),
                    enrollment_id = table.Column<Guid>(type: "TEXT", nullable: true),
                    protected_secret = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    enrollment_expires_at = table.Column<long>(type: "INTEGER", nullable: true),
                    failed_attempts = table.Column<int>(type: "INTEGER", nullable: false),
                    consumed = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_identity_access_links", x => x.id);
                    table.ForeignKey(
                        name: "FK_identity_access_links_auth_users_user_id",
                        column: x => x.user_id,
                        principalTable: "auth_users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_identity_access_links_expires_at",
                table: "identity_access_links",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "ix_identity_access_links_user_id",
                table: "identity_access_links",
                column: "user_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "identity_access_links");
        }
    }
}
