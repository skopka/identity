namespace Skopka.Identity.Credentials;

public sealed class PasswordPolicyOptions
{
    public const int MinimumAllowedLength = 8;
    public const int MinimumSupportedMaximumLength = 64;
    public const int MaximumAllowedLength = 1_024;

    public int MinimumLength { get; set; } = 15;

    public int MaximumLength { get; set; } = 128;
}
