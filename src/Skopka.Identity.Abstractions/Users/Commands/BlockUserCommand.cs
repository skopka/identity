namespace Skopka.Identity.Users.Commands;

public record BlockUserCommand(Guid UserId, long ExpectedVersion, DateTimeOffset? Until, string? Reason = null);
