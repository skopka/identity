namespace Skopka.Identity.Authentication;

public sealed record AuthenticatePasswordCommand(
    PasswordLoginHandle Handle,
    string Login,
    string Password,
    string? ClientKey = null)
{
    /// <summary>
    /// Trusted, server-selected phone scope for <see cref="PasswordLoginHandle.Phone"/>.
    /// <see langword="null"/> searches the default scope only. Ignored by the other modes:
    /// <see cref="PasswordLoginHandle.Automatic"/> searches every scope, so a phone shared
    /// across scopes is ambiguous there and fails as invalid credentials.
    /// </summary>
    public string? PhoneScope { get; init; }
}
