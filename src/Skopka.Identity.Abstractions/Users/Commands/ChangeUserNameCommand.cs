namespace Skopka.Identity.Users.Commands;

public record ChangeUserNameCommand(Guid UserId, long ExpectedVersion, string NewUserName);
