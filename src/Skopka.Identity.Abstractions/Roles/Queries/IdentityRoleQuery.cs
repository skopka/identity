namespace Skopka.Identity.Roles.Queries;

public sealed record IdentityRoleQuery(
    string? Search = null,
    int PageSize = IdentityRoleQueryLimits.DefaultPageSize,
    IdentityRoleCursor? Cursor = null);
