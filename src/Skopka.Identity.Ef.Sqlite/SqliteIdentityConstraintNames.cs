namespace Skopka.Identity.Ef.Sqlite;

internal static class SqliteIdentityConstraintNames
{
    public const string UserName = "ux_auth_users_normalized_user_name";
    public const string Email = "ux_auth_users_normalized_email";
    public const string Phone = "ux_auth_users_normalized_phone";
    public const string LoginIdentifier =
        "ux_identity_login_identifiers_active_normalized_key";
    public const string ActiveVerificationIntent =
        "ux_verification_challenges_active_intent";
}
