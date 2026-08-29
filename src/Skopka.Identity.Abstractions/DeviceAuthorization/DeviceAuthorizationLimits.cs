namespace Skopka.Identity.DeviceAuthorization;

public static class DeviceAuthorizationLimits
{
    public const int MaximumDeviceCodeLength = 128;
    public const int MaximumBrowserVerifierLength = 256;
    public const int VerifierHashLength = 64;
    public const int MaximumUserCodeLength = 32;
    public const int MaximumUserCodeAlphabetLength = 64;
    public const int MaximumIpAddressLength = 64;
    public const int MaximumUserAgentLength = 512;
    public const int MaximumDeviceDisplayNameLength = 256;
    public const int MaximumClientIdLength = 128;
    public const int MaximumReturnUrlLength = 2_048;
}
