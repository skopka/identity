using Skopka.Identity.ExternalLogins;

namespace Skopka.Identity.SignInMethods;

public sealed record SignInMethodSnapshot(
    Guid UserId,
    long Version,
    bool HasPassword,
    IReadOnlyList<ExternalLoginInfo> ExternalLogins);
