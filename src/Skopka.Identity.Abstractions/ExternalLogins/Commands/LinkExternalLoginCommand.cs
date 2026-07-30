namespace Skopka.Identity.ExternalLogins;

public sealed record LinkExternalLoginCommand(
    Guid UserId,
    long ExpectedVersion,
    ExternalLoginKey Login);
