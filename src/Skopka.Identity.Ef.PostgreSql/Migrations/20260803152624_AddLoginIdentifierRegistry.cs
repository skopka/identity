using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Skopka.Identity.Ef.Migrations
{
    /// <inheritdoc />
    public partial class AddLoginIdentifierRegistry : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "identity_login_identifiers",
                columns: table => new
                {
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    normalized_key = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    is_active = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_identity_login_identifiers", x => new { x.user_id, x.normalized_key });
                    table.ForeignKey(
                        name: "fk_identity_login_identifiers_auth_users_user_id",
                        column: x => x.user_id,
                        principalTable: "auth_users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.Sql(
                """
                DO $migration$
                BEGIN
                    IF EXISTS (
                        SELECT 1
                        FROM auth_users AS users
                        INNER JOIN user_profiles AS profiles
                            ON profiles.user_id = users.id
                        WHERE CHAR_LENGTH(profiles.user_name) > 512
                           OR CHAR_LENGTH(profiles.email) > 512
                           OR CHAR_LENGTH(profiles.phone) > 512
                           OR CHAR_LENGTH(users.normalized_user_name) > 512
                           OR CHAR_LENGTH(users.normalized_email) > 512
                           OR CHAR_LENGTH(users.normalized_phone) > 512
                    ) THEN
                        RAISE EXCEPTION
                            'Legacy identity handles exceed the 512-character login-identifier limit. Clean the data or customize this migration before upgrading.';
                    END IF;

                    IF EXISTS (
                        SELECT 1
                        FROM auth_users AS users
                        INNER JOIN user_profiles AS profiles
                            ON profiles.user_id = users.id
                        CROSS JOIN LATERAL (
                            SELECT
                                REGEXP_REPLACE(
                                    profiles.phone,
                                    '(^[[:space:]]+|[[:space:]]+$)',
                                    '',
                                    'g') AS trimmed_value,
                                REGEXP_REPLACE(
                                    profiles.phone,
                                    '[^0-9]',
                                    '',
                                    'g') AS digits
                        ) AS prepared_phone
                        WHERE (
                                profiles.phone IS NULL
                                AND users.normalized_phone IS NOT NULL)
                           OR (
                                profiles.phone IS NOT NULL
                                AND (
                                    prepared_phone.trimmed_value
                                        !~ '^\+?[0-9[:space:]().-]+$'
                                    OR CHAR_LENGTH(prepared_phone.digits)
                                        NOT BETWEEN 8 AND 15
                                    OR users.normalized_phone
                                        IS DISTINCT FROM prepared_phone.digits
                                ))
                    ) THEN
                        RAISE EXCEPTION
                            'Legacy phone handles do not satisfy the default login-identifier policy. Clean the data or customize this migration before upgrading.';
                    END IF;
                END
                $migration$;
                """);

            migrationBuilder.Sql(
                """
                INSERT INTO identity_login_identifiers
                    (user_id, normalized_key, is_active)
                SELECT DISTINCT
                    prepared.user_id,
                    prepared.normalized_key,
                    prepared.is_active
                FROM (
                    SELECT
                        users.id AS user_id,
                        users.normalized_user_name AS normalized_key,
                        users.deleted_at IS NULL AS is_active
                    FROM auth_users AS users

                    UNION ALL

                    SELECT
                        users.id,
                        users.normalized_email,
                        users.deleted_at IS NULL
                    FROM auth_users AS users

                    UNION ALL

                    SELECT
                        users.id,
                        users.normalized_phone,
                        users.deleted_at IS NULL
                    FROM auth_users AS users

                    UNION ALL

                    SELECT
                        users.id,
                        REGEXP_REPLACE(
                            profiles.phone,
                            '(^[[:space:]]+|[[:space:]]+$)',
                            '',
                            'g'),
                        users.deleted_at IS NULL
                    FROM auth_users AS users
                    INNER JOIN user_profiles AS profiles
                        ON profiles.user_id = users.id
                    WHERE profiles.phone IS NOT NULL

                    UNION ALL

                    SELECT
                        users.id,
                        REGEXP_REPLACE(
                            raw_handles.value,
                            '[^0-9]',
                            '',
                            'g'),
                        users.deleted_at IS NULL
                    FROM auth_users AS users
                    INNER JOIN user_profiles AS profiles
                        ON profiles.user_id = users.id
                    CROSS JOIN LATERAL (
                        VALUES
                            (profiles.user_name),
                            (profiles.email),
                            (profiles.phone)
                    ) AS raw_handles(value)
                    WHERE REGEXP_REPLACE(
                            raw_handles.value,
                            '(^[[:space:]]+|[[:space:]]+$)',
                            '',
                            'g')
                        ~ '^\+?[0-9[:space:]().-]+$'
                      AND CHAR_LENGTH(
                            REGEXP_REPLACE(
                                raw_handles.value,
                                '[^0-9]',
                                '',
                                'g')) BETWEEN 8 AND 15
                ) AS prepared
                WHERE prepared.normalized_key IS NOT NULL
                  AND prepared.normalized_key <> '';
                """);

            migrationBuilder.Sql(
                """
                DO $migration$
                BEGIN
                    IF EXISTS (
                        SELECT normalized_key
                        FROM identity_login_identifiers
                        WHERE is_active = TRUE
                        GROUP BY normalized_key
                        HAVING COUNT(*) > 1
                    ) THEN
                        RAISE EXCEPTION
                            'Active users share a normalized login identifier. Resolve cross-user handle aliases before upgrading.';
                    END IF;
                END
                $migration$;
                """);

            migrationBuilder.CreateIndex(
                name: "ux_identity_login_identifiers_active_normalized_key",
                table: "identity_login_identifiers",
                column: "normalized_key",
                unique: true,
                filter: "is_active = TRUE");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "identity_login_identifiers");
        }
    }
}
