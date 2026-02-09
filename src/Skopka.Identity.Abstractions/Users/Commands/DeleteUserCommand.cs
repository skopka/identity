namespace Skopka.Identity.Users.Commands;

public record DeleteUserCommand(Guid UserId, long ExpectedVersion, string? Reason = null);
