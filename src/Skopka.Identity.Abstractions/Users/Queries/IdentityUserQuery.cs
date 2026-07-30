namespace Skopka.Identity.Users.Queries;

public sealed record IdentityUserQuery(
    string? Search = null,
    IdentityUserStatus Status = IdentityUserStatus.Any,
    UserFlags RequiredFlags = UserFlags.None,
    int PageSize = IdentityUserQueryLimits.DefaultPageSize,
    IdentityUserCursor? Cursor = null);
