using System.Security.Cryptography;

namespace Skopka.Identity.Security;

public sealed class DefaultSecurityStampGenerator : ISecurityStampGenerator
{
    private const int StampSize = 32;

    public string Generate()
        => Convert.ToHexString(RandomNumberGenerator.GetBytes(StampSize));
}
