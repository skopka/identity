using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Skopka.Identity.Ef.Migrations
{
    /// <inheritdoc />
    public partial class InitialIdentitySchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "auth_users",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    flags = table.Column<int>(type: "INTEGER", nullable: false),
                    normalized_user_name = table.Column<string>(type: "TEXT", nullable: true),
                    normalized_email = table.Column<string>(type: "TEXT", nullable: true),
                    normalized_phone = table.Column<string>(type: "TEXT", nullable: true),
                    email_confirmed = table.Column<bool>(type: "INTEGER", nullable: false),
                    phone_confirmed = table.Column<bool>(type: "INTEGER", nullable: false),
                    version = table.Column<long>(type: "INTEGER", nullable: false),
                    security_stamp = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    deleted_at = table.Column<long>(type: "INTEGER", nullable: true),
                    blocked_at = table.Column<long>(type: "INTEGER", nullable: true),
                    blocked_until = table.Column<long>(type: "INTEGER", nullable: true),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false),
                    modified_at = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_auth_users", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "identity_rate_limit_buckets",
                columns: table => new
                {
                    scope = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    partition_version = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    key_hash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    window_started_at = table.Column<long>(type: "INTEGER", nullable: false),
                    hit_count = table.Column<int>(type: "INTEGER", nullable: false),
                    last_hit_at = table.Column<long>(type: "INTEGER", nullable: false),
                    version = table.Column<long>(type: "INTEGER", nullable: false),
                    modified_at = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_identity_rate_limit_buckets", x => new { x.scope, x.partition_version, x.key_hash });
                });

            migrationBuilder.CreateTable(
                name: "identity_roles",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    normalized_name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    description = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    parent_id = table.Column<Guid>(type: "TEXT", nullable: true),
                    version = table.Column<long>(type: "INTEGER", nullable: false),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false),
                    modified_at = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_identity_roles", x => x.id);
                    table.ForeignKey(
                        name: "fk_identity_roles_identity_roles_parent_id",
                        column: x => x.parent_id,
                        principalTable: "identity_roles",
                        principalColumn: "id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "identity_login_identifiers",
                columns: table => new
                {
                    user_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    normalized_key = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    is_active = table.Column<bool>(type: "INTEGER", nullable: false)
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

            migrationBuilder.CreateTable(
                name: "identity_refresh_sessions",
                columns: table => new
                {
                    token_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    session_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    user_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    token_hash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    security_stamp = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    client_name = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    device_name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    version = table.Column<long>(type: "INTEGER", nullable: false),
                    expires_at = table.Column<long>(type: "INTEGER", nullable: false),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false),
                    modified_at = table.Column<long>(type: "INTEGER", nullable: false),
                    rotated_at = table.Column<long>(type: "INTEGER", nullable: true),
                    revoked_at = table.Column<long>(type: "INTEGER", nullable: true),
                    replaced_by_token_id = table.Column<Guid>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_identity_refresh_sessions", x => x.token_id);
                    table.ForeignKey(
                        name: "FK_identity_refresh_sessions_auth_users_user_id",
                        column: x => x.user_id,
                        principalTable: "auth_users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "user_credentials",
                columns: table => new
                {
                    user_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    password_verifier = table.Column<string>(type: "TEXT", nullable: true),
                    updated_at = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_user_credentials", x => x.user_id);
                    table.ForeignKey(
                        name: "FK_user_credentials_auth_users_user_id",
                        column: x => x.user_id,
                        principalTable: "auth_users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "user_external_logins",
                columns: table => new
                {
                    provider = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    subject = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    user_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_user_external_logins", x => new { x.provider, x.subject });
                    table.ForeignKey(
                        name: "fk_user_external_logins_auth_users_user_id",
                        column: x => x.user_id,
                        principalTable: "auth_users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "user_profiles",
                columns: table => new
                {
                    user_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    user_name = table.Column<string>(type: "TEXT", nullable: true),
                    email = table.Column<string>(type: "TEXT", nullable: true),
                    phone = table.Column<string>(type: "TEXT", nullable: true),
                    profile = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_user_profiles", x => x.user_id);
                    table.ForeignKey(
                        name: "FK_user_profiles_auth_users_user_id",
                        column: x => x.user_id,
                        principalTable: "auth_users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "verification_challenges",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    user_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    intent_hash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    purpose = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    binding = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    method = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    verifier = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    security_stamp = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    failed_attempt_count = table.Column<int>(type: "INTEGER", nullable: false),
                    max_attempts = table.Column<int>(type: "INTEGER", nullable: false),
                    state = table.Column<int>(type: "INTEGER", nullable: false),
                    proof_hash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    proof_expires_at = table.Column<long>(type: "INTEGER", nullable: true),
                    version = table.Column<long>(type: "INTEGER", nullable: false),
                    expires_at = table.Column<long>(type: "INTEGER", nullable: false),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false),
                    modified_at = table.Column<long>(type: "INTEGER", nullable: false),
                    verified_at = table.Column<long>(type: "INTEGER", nullable: true),
                    consumed_at = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_verification_challenges", x => x.id);
                    table.ForeignKey(
                        name: "FK_verification_challenges_auth_users_user_id",
                        column: x => x.user_id,
                        principalTable: "auth_users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "identity_user_roles",
                columns: table => new
                {
                    user_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    role_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_identity_user_roles", x => new { x.user_id, x.role_id });
                    table.ForeignKey(
                        name: "fk_identity_user_roles_auth_users_user_id",
                        column: x => x.user_id,
                        principalTable: "auth_users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_identity_user_roles_identity_roles_role_id",
                        column: x => x.role_id,
                        principalTable: "identity_roles",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ux_auth_users_normalized_email",
                table: "auth_users",
                column: "normalized_email",
                unique: true,
                filter: "deleted_at IS NULL AND normalized_email IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ux_auth_users_normalized_phone",
                table: "auth_users",
                column: "normalized_phone",
                unique: true,
                filter: "deleted_at IS NULL AND normalized_phone IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ux_auth_users_normalized_user_name",
                table: "auth_users",
                column: "normalized_user_name",
                unique: true,
                filter: "deleted_at IS NULL AND normalized_user_name IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ux_identity_login_identifiers_active_normalized_key",
                table: "identity_login_identifiers",
                column: "normalized_key",
                unique: true,
                filter: "is_active = 1");

            migrationBuilder.CreateIndex(
                name: "ix_identity_refresh_sessions_expires_at",
                table: "identity_refresh_sessions",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "ix_identity_refresh_sessions_session_id",
                table: "identity_refresh_sessions",
                column: "session_id");

            migrationBuilder.CreateIndex(
                name: "ix_identity_refresh_sessions_user_id",
                table: "identity_refresh_sessions",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "ix_identity_roles_parent_id",
                table: "identity_roles",
                column: "parent_id");

            migrationBuilder.CreateIndex(
                name: "ux_identity_roles_normalized_name",
                table: "identity_roles",
                column: "normalized_name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_identity_user_roles_role_id",
                table: "identity_user_roles",
                column: "role_id");

            migrationBuilder.CreateIndex(
                name: "ix_user_external_logins_user_id",
                table: "user_external_logins",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "ix_verification_challenges_user_state",
                table: "verification_challenges",
                columns: new[] { "user_id", "state" });

            migrationBuilder.CreateIndex(
                name: "ux_verification_challenges_active_intent",
                table: "verification_challenges",
                columns: new[] { "user_id", "intent_hash" },
                unique: true,
                filter: "state IN (0, 1)");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "identity_login_identifiers");

            migrationBuilder.DropTable(
                name: "identity_rate_limit_buckets");

            migrationBuilder.DropTable(
                name: "identity_refresh_sessions");

            migrationBuilder.DropTable(
                name: "identity_user_roles");

            migrationBuilder.DropTable(
                name: "user_credentials");

            migrationBuilder.DropTable(
                name: "user_external_logins");

            migrationBuilder.DropTable(
                name: "user_profiles");

            migrationBuilder.DropTable(
                name: "verification_challenges");

            migrationBuilder.DropTable(
                name: "identity_roles");

            migrationBuilder.DropTable(
                name: "auth_users");
        }
    }
}
