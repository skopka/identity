namespace Skopka.Identity.Tokens;

public interface IIdentityActionTokenProvider
{
    string Generate(IdentityActionTokenPayload payload);

    bool TryRead(
        string token,
        IdentityActionTokenPurpose expectedPurpose,
        out IdentityActionTokenPayload? payload);
}
