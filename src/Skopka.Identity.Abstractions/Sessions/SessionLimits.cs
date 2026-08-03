namespace Skopka.Identity.Sessions;

public static class SessionLimits
{
    public const int MaximumTokenLength = 2_048;
    public const int TokenHashLength = 64;
    public const int SecurityStampLength = 64;
    public const int MinimumJwtSigningKeyLength = 32;
    public const int MaximumJwtSigningKeyIdLength = 64;
    public const int MaximumJwtSigningKeys = 8;
    public const int MaximumClientNameLength = 128;
    public const int MaximumDeviceNameLength = 256;
}
