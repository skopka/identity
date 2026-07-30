namespace Skopka.Identity.Users.Queries;

public sealed record IdentityUserStoreQuery(
    string? NormalizedUserName,
    string? NormalizedEmail,
    string? NormalizedPhone,
    Guid? Id,
    IdentityUserStatus Status,
    UserFlags RequiredFlags,
    int PageSize,
    IdentityUserCursor? Cursor);
