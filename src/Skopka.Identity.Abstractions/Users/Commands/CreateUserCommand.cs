namespace Skopka.Identity.Users.Commands;

public record CreateUserCommand(string? UserName, string? Email, string? Phone, UserFlags Flags = UserFlags.None, Guid? IdempotencyKey = null)
{
    /// <summary>
    /// Trusted, server-selected scope of <see cref="Phone"/>. <see langword="null"/> places the
    /// phone in <see cref="IdentityPhoneScopes.Default"/>. Ignored when there is no phone.
    /// </summary>
    public string? PhoneScope { get; init; }
}

public record CreateUserCommand<TProfile>(string? UserName, string? Email, string? Phone, TProfile Profile, UserFlags Flags = UserFlags.None, Guid? IdempotencyKey = null)
    : CreateUserCommand(UserName, Email, Phone, Flags, IdempotencyKey);
