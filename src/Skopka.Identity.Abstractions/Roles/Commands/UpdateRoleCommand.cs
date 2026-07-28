namespace Skopka.Identity.Roles.Commands;

public sealed record UpdateRoleCommand(
    Guid RoleId,
    long ExpectedVersion,
    string Name,
    string? Description = null,
    Guid? ParentId = null);
