namespace Skopka.Identity.Roles;

public sealed record NewIdentityRole(
    string Name,
    string NormalizedName,
    string? Description,
    Guid? ParentId);
