namespace Skopka.Identity.Roles.Commands;

public sealed record RemoveRoleCommand(
    Guid UserId,
    Guid RoleId);
