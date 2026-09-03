namespace Skopka.Identity.WebAuthn;

public static class WebAuthnLimits
{
    public const int MinimumChallengeLength = 16;
    public const int MaximumChallengeLength = 128;

    public const int MinimumCredentialIdLength = 16;
    public const int MaximumCredentialIdLength = 1023;

    public const int MaximumPublicKeyLength = 1024;

    public const int MaximumClientDataLength = 8192;
    public const int MaximumAttestationObjectLength = 16384;
    public const int MaximumAuthenticatorDataLength = 4096;
    public const int MaximumSignatureLength = 1024;

    public const int MaximumLabelLength = 64;
}
