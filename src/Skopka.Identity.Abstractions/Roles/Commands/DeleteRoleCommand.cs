namespace Skopka.Identity.Roles.Commands;

public sealed record DeleteRoleCommand(
    Guid RoleId,
    long ExpectedVersion);
