namespace Skopka.Identity.Sessions;

public interface IIdentityAccessTokenProvider
{
    string Generate(IdentityAccessTokenPayload payload);

    Task<IdentityAccessTokenPayload?> ValidateAsync(
        string token,
        CancellationToken ct);
}
