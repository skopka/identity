namespace Skopka.Identity.Users.Queries;

public static class IdentityUserQueryLimits
{
    public const int DefaultPageSize = 50;
    public const int MaximumPageSize = 100;
    public const int MaximumSearchLength = 512;

    /// <summary>Maximum distinct role ids in one role-membership filter.</summary>
    public const int MaximumRoleIds = 50;
}
