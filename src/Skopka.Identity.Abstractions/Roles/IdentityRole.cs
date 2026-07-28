namespace Skopka.Identity.Roles;

public sealed record IdentityRole(
    Guid Id,
    string Name,
    string? Description,
    Guid? ParentId,
    long Version,
    DateTimeOffset CreatedAt,
    DateTimeOffset ModifiedAt);
