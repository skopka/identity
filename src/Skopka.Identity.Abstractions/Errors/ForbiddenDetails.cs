using Skopka.Identity.Users;

namespace Skopka.Identity.Errors;

public sealed record ForbiddenDetails(UserFlags Flags);
