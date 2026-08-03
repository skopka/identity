namespace Skopka.Identity.Ef.PostgreSql;

internal static class PostgreSqlIdentityConstraintNames
{
    public const string UserName = "ux_auth_users_normalized_user_name";
    public const string Email = "ux_auth_users_normalized_email";
    public const string Phone = "ux_auth_users_normalized_phone";
    public const string LoginIdentifier =
        "ux_identity_login_identifiers_active_normalized_key";
    public const string ActiveVerificationIntent =
        "ux_verification_challenges_active_intent";
    public const string ExternalLogin = "pk_user_external_logins";
    public const string RoleName = "ux_identity_roles_normalized_name";
    public const string UserRole = "pk_identity_user_roles";
    public const string RoleParent = "fk_identity_roles_identity_roles_parent_id";
    public const string UserRoleUser = "fk_identity_user_roles_auth_users_user_id";
    public const string UserRoleRole = "fk_identity_user_roles_identity_roles_role_id";
}
