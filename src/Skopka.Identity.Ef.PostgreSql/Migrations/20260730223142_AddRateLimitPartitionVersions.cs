using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Skopka.Identity.Ef.Migrations
{
    /// <inheritdoc />
    public partial class AddRateLimitPartitionVersions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropPrimaryKey(
                name: "PK_identity_rate_limit_buckets",
                table: "identity_rate_limit_buckets");

            migrationBuilder.AddColumn<string>(
                name: "partition_version",
                table: "identity_rate_limit_buckets",
                type: "character varying(64)",
                maxLength: 64,
                nullable: false,
                defaultValue: "legacy");

            migrationBuilder.AddPrimaryKey(
                name: "PK_identity_rate_limit_buckets",
                table: "identity_rate_limit_buckets",
                columns: new[] { "scope", "partition_version", "key_hash" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropPrimaryKey(
                name: "PK_identity_rate_limit_buckets",
                table: "identity_rate_limit_buckets");

            migrationBuilder.DropColumn(
                name: "partition_version",
                table: "identity_rate_limit_buckets");

            migrationBuilder.AddPrimaryKey(
                name: "PK_identity_rate_limit_buckets",
                table: "identity_rate_limit_buckets",
                columns: new[] { "scope", "key_hash" });
        }
    }
}
