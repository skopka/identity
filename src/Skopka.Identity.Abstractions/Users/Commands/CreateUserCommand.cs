namespace Skopka.Identity.Users.Commands;

public record CreateUserCommand(string? UserName, string? Email, string? Phone, UserFlags Flags = UserFlags.None, Guid? IdempotencyKey = null);

public record CreateUserCommand<TProfile>(string? UserName, string? Email, string? Phone, TProfile Profile, UserFlags Flags = UserFlags.None, Guid? IdempotencyKey = null)
    : CreateUserCommand(UserName, Email, Phone, Flags, IdempotencyKey);
