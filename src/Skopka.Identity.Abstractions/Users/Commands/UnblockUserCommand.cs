namespace Skopka.Identity.Users.Commands;

public record UnblockUserCommand(Guid UserId, long ExpectedVersion);
