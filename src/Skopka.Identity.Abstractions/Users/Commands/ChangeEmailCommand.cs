namespace Skopka.Identity.Users.Commands;

public record ChangeEmailCommand(Guid UserId, long ExpectedVersion, string? NewEmail);
