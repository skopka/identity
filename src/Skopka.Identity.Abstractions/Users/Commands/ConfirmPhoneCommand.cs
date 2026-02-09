namespace Skopka.Identity.Users.Commands;

public record ConfirmPhoneCommand(Guid UserId, string Phone);
