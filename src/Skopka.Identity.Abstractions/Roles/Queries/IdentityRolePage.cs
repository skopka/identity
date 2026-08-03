namespace Skopka.Identity.Roles.Queries;

public sealed record IdentityRolePage(
    IReadOnlyList<IdentityRole> Items,
    IdentityRoleCursor? NextCursor);
