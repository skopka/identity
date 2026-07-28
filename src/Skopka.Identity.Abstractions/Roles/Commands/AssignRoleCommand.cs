namespace Skopka.Identity.Roles.Commands;

public sealed record AssignRoleCommand(
    Guid UserId,
    Guid RoleId);
