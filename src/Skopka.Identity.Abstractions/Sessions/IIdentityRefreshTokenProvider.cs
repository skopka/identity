namespace Skopka.Identity.Sessions;

public interface IIdentityRefreshTokenProvider
{
    GeneratedRefreshToken Generate(Guid tokenId);

    bool TryRead(
        string token,
        out Guid tokenId,
        out string? tokenHash);
}
