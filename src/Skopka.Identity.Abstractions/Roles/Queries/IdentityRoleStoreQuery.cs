namespace Skopka.Identity.Roles.Queries;

public sealed record IdentityRoleStoreQuery(
    string? NormalizedName,
    int PageSize,
    IdentityRoleCursor? Cursor);
