namespace Skopka.Identity.Users.Commands;

public record ChangePhoneCommand(Guid UserId, long ExpectedVersion, string? NewPhone);
