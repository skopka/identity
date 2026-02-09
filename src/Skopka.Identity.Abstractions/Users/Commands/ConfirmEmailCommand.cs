namespace Skopka.Identity.Users.Commands;

public record ConfirmEmailCommand(Guid UserId, string Email);
