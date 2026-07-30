namespace Skopka.Identity.ExternalLogins;

public sealed record ExternalLoginInfo(
    Guid UserId,
    ExternalLoginKey Login,
    DateTimeOffset CreatedAt);
