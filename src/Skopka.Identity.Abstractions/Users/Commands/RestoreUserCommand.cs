namespace Skopka.Identity.Users.Commands;

public record RestoreUserCommand(Guid UserId, long ExpectedVersion);
