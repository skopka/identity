namespace Skopka.Identity.Authentication;

public sealed record AuthenticatePasswordCommand(
    PasswordLoginHandle Handle,
    string Login,
    string Password,
    string? ClientKey = null)
{
    /// <summary>
    /// Trusted, server-selected phone scope.
    /// </summary>
    /// <remarks>
    /// With <see cref="PasswordLoginHandle.Phone"/>, <see langword="null"/> searches the
    /// default scope only. With <see cref="PasswordLoginHandle.Automatic"/>, a non-null
    /// scope limits the entered number to accounts whose phone is in that scope, while
    /// user names and emails still match in every scope; <see langword="null"/> keeps the
    /// 0.19.0 behavior of searching every scope, where a number shared across scopes is
    /// ambiguous. Pass <see cref="Users.IdentityPhoneScopes.Default"/> explicitly for a
    /// site that uses the default scope. Ignored by the user-name and email modes.
    /// </remarks>
    public string? PhoneScope { get; init; }
}
