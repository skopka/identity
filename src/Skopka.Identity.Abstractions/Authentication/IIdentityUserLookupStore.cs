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

    Task<IdentityUser<TProfile>?> FindActiveByNormalizedPhoneAsync(
        string normalizedPhone,
        CancellationToken ct)
        => Task.FromResult<IdentityUser<TProfile>?>(null);

    Task<IReadOnlyList<IdentityUser<TProfile>>>
        FindActiveByNormalizedLoginIdentifiersAsync(
            IReadOnlyCollection<string> normalizedKeys,
            CancellationToken ct)
        => Task.FromResult<IReadOnlyList<IdentityUser<TProfile>>>(
            Array.Empty<IdentityUser<TProfile>>());
}
