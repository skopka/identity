namespace Skopka.Identity.Sessions;

public static class SessionLimits
{
    public const int MaximumTokenLength = 2_048;
    public const int TokenHashLength = 64;
    public const int SecurityStampLength = 64;
    public const int MaximumClientNameLength = 128;
    public const int MaximumDeviceNameLength = 256;
}
