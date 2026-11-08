namespace Skopka.Identity.Users.Queries;

public sealed record IdentityUserQuery(
    string? Search = null,
    IdentityUserStatus Status = IdentityUserStatus.Any,
    UserFlags RequiredFlags = UserFlags.None,
    int PageSize = IdentityUserQueryLimits.DefaultPageSize,
    IdentityUserCursor? Cursor = null)
{
    /// <summary>
    /// Limits results to users with a direct membership in at least one of these roles.
    /// <see langword="null"/> applies no role filter; an empty collection is rejected so a
    /// caller cannot widen "members of nothing" into "every user" by accident.
    /// </summary>
    /// <remarks>
    /// Search, status, flags and the <c>(CreatedAt, Id)</c> cursor apply unchanged.
    /// At most <see cref="IdentityUserQueryLimits.MaximumRoleIds"/> distinct ids.
    /// Unknown role ids simply match no users.
    /// </remarks>
    public IReadOnlyCollection<Guid>? RoleIds { get; init; }
}
