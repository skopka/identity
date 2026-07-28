namespace Skopka.Identity.Roles.Commands;

public sealed record CreateRoleCommand(
    string Name,
    string? Description = null,
    Guid? ParentId = null);
