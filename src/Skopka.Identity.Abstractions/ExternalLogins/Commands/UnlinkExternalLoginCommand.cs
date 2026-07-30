namespace Skopka.Identity.ExternalLogins;

public sealed record UnlinkExternalLoginCommand(
    Guid UserId,
    long ExpectedVersion,
    ExternalLoginKey Login);
