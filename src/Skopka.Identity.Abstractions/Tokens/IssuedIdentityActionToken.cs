namespace Skopka.Identity.Tokens;

public sealed record IssuedIdentityActionToken(
    string Token,
    DateTimeOffset ExpiresAt);
