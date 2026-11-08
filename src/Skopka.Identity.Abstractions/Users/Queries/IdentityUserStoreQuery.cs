namespace Skopka.Identity.Users.Queries;

public sealed record IdentityUserStoreQuery(
    string? NormalizedUserName,
    string? NormalizedEmail,
    string? NormalizedPhone,
    Guid? Id,
    IdentityUserStatus Status,
    UserFlags RequiredFlags,
    int PageSize,
    IdentityUserCursor? Cursor)
{
    /// <summary>
    /// Distinct, validated role ids; a user matches when it is a direct member of any of
    /// them. <see langword="null"/> means no role filter. Never empty.
    /// </summary>
    public IReadOnlyList<Guid>? RoleIds { get; init; }
}
