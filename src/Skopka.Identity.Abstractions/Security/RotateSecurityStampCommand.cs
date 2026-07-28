namespace Skopka.Identity.Security;

public sealed record RotateSecurityStampCommand(
    Guid UserId,
    long ExpectedVersion);
