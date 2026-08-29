using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Skopka.Identity.Ef.Migrations
{
    /// <inheritdoc />
    public partial class AddDeviceAuthorization : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "device_authorization_requests",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    device_code = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    browser_verifier_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    user_code = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    state = table.Column<int>(type: "integer", nullable: false),
                    ip_address = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    user_agent = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    device_display_name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    client_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    return_url = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: true),
                    session_client_name = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    session_device_name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    resolved_by_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    approved_security_stamp = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    consumption_id = table.Column<Guid>(type: "uuid", nullable: true),
                    session_id = table.Column<Guid>(type: "uuid", nullable: true),
                    version = table.Column<long>(type: "bigint", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    modified_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    resolved_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    consumed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_device_authorization_requests", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "ix_device_authorization_requests_state_expires_at",
                table: "device_authorization_requests",
                columns: new[] { "state", "expires_at" });

            migrationBuilder.CreateIndex(
                name: "ux_device_authorization_requests_device_code",
                table: "device_authorization_requests",
                column: "device_code",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "device_authorization_requests");
        }
    }
}
