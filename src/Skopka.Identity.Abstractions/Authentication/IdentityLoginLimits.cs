namespace Skopka.Identity.Authentication;

public static class IdentityLoginLimits
{
    public const int MaximumLoginLength = 512;
    public const int MaximumAutomaticLoginIdentifiers = 3;
    public const int MaximumResolvedUsers = 2;
    public const int MinimumPhoneDigits = 8;
    public const int MaximumPhoneDigits = 15;
}
