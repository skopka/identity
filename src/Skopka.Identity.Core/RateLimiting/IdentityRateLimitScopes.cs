namespace Skopka.Identity.RateLimiting;

internal static class IdentityRateLimitScopes
{
    public const string PasswordAccount = "password.account";
    public const string PasswordClient = "password.client";
    public const string VerificationAccount = "verification.account";
    public const string VerificationIntent = "verification.intent";
    public const string VerificationClient = "verification.client";
}
