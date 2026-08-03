using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Skopka.Identity.Ef.PostgreSql;

#nullable disable

namespace Skopka.Identity.Ef.Migrations;

[DbContext(typeof(PostgreSqlIdentityDbContext<PostgreSqlIdentityDesignTimeProfile>))]
[Migration("20260803200000_SupersedeVerificationChallenges")]
public partial class SupersedeVerificationChallenges : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "intent_hash",
            table: "verification_challenges",
            type: "character varying(64)",
            maxLength: 64,
            nullable: true);

        migrationBuilder.Sql(
            """
            UPDATE verification_challenges
            SET intent_hash = ENCODE(
                SHA256(
                    INT4SEND(OCTET_LENGTH(CONVERT_TO(purpose, 'UTF8')))
                    || CONVERT_TO(purpose, 'UTF8')
                    || INT4SEND(OCTET_LENGTH(CONVERT_TO(binding, 'UTF8')))
                    || CONVERT_TO(binding, 'UTF8')
                    || INT4SEND(OCTET_LENGTH(CONVERT_TO(method, 'UTF8')))
                    || CONVERT_TO(method, 'UTF8')),
                'hex');
            """);

        migrationBuilder.Sql(
            """
            WITH ranked_challenges AS (
                SELECT
                    id,
                    ROW_NUMBER() OVER (
                        PARTITION BY user_id, intent_hash
                        ORDER BY created_at DESC, id DESC) AS intent_rank
                FROM verification_challenges
                WHERE state IN (0, 1)
            )
            UPDATE verification_challenges AS challenges
            SET
                state = 4,
                version = challenges.version + 1,
                modified_at = CURRENT_TIMESTAMP
            FROM ranked_challenges
            WHERE challenges.id = ranked_challenges.id
              AND ranked_challenges.intent_rank > 1;
            """);

        migrationBuilder.AlterColumn<string>(
            name: "intent_hash",
            table: "verification_challenges",
            type: "character varying(64)",
            maxLength: 64,
            nullable: false,
            oldClrType: typeof(string),
            oldType: "character varying(64)",
            oldMaxLength: 64,
            oldNullable: true);

        migrationBuilder.CreateIndex(
            name: "ux_verification_challenges_active_intent",
            table: "verification_challenges",
            columns: new[] { "user_id", "intent_hash" },
            unique: true,
            filter: "state IN (0, 1)");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropIndex(
            name: "ux_verification_challenges_active_intent",
            table: "verification_challenges");

        migrationBuilder.DropColumn(
            name: "intent_hash",
            table: "verification_challenges");
    }
}
