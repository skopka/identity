namespace Skopka.Identity.Authentication;

public sealed record AuthenticatePasswordCommand(
    PasswordLoginHandle Handle,
    string Login,
    string Password);
