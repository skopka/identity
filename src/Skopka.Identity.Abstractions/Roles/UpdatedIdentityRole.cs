namespace Skopka.Identity.Roles;

public sealed record UpdatedIdentityRole(
    string Name,
    string NormalizedName,
    string? Description,
    Guid? ParentId);
