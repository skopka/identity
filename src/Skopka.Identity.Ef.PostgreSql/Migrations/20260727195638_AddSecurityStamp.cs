using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Skopka.Identity.Ef.Migrations
{
    /// <inheritdoc />
    public partial class AddSecurityStamp : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "security_stamp",
                table: "auth_users",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.Sql(
                """
                UPDATE auth_users
                SET security_stamp = replace(gen_random_uuid()::text, '-', '')
                WHERE security_stamp IS NULL;
                """);

            migrationBuilder.AlterColumn<string>(
                name: "security_stamp",
                table: "auth_users",
                type: "character varying(64)",
                maxLength: 64,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(64)",
                oldMaxLength: 64,
                oldNullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "security_stamp",
                table: "auth_users");
        }
    }
}
