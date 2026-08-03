namespace Skopka.Identity.Roles.Queries;

public static class IdentityRoleQueryLimits
{
    public const int DefaultPageSize = 50;
    public const int MaximumPageSize = 100;
    public const int MaximumSearchLength =
        IdentityRoleLimits.MaximumNameLength;
}
