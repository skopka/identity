namespace Skopka.Identity.ExternalLogins;

public sealed record ExternalLoginKey(
    string Provider,
    string Subject);
