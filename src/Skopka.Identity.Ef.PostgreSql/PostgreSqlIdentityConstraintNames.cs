namespace Skopka.Identity.Ef.PostgreSql;

internal static class PostgreSqlIdentityConstraintNames
{
    public const string UserName = "ux_auth_users_normalized_user_name";
    public const string Email = "ux_auth_users_normalized_email";
    public const string Phone = "ux_auth_users_normalized_phone";
}
