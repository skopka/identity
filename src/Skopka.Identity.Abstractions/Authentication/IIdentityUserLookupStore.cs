using Skopka.Identity.Users;

namespace Skopka.Identity.Authentication;

public interface IIdentityUserLookupStore<TProfile>
{
    Task<IdentityUser<TProfile>?> FindActiveByNormalizedUserNameAsync(
        string normalizedUserName,
        CancellationToken ct);

    Task<IdentityUser<TProfile>?> FindActiveByNormalizedEmailAsync(
        string normalizedEmail,
        CancellationToken ct);
}
