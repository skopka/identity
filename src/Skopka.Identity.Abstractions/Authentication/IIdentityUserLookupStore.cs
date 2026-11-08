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

    /// <summary>
    /// Finds the active user holding the phone in the given scope. Stores without scope
    /// support resolve only the default scope.
    /// </summary>
    Task<IdentityUser<TProfile>?> FindActiveByNormalizedPhoneAsync(
        string normalizedPhone,
        string phoneScope,
        CancellationToken ct)
        => string.IsNullOrEmpty(phoneScope)
            ? FindActiveByNormalizedPhoneAsync(normalizedPhone, ct)
            : Task.FromResult<IdentityUser<TProfile>?>(null);

    /// <summary>
    /// Resolves the normalized keys across every phone scope; callers treat several
    /// matching users as ambiguous.
    /// </summary>
    Task<IReadOnlyList<IdentityUser<TProfile>>>
        FindActiveByNormalizedLoginIdentifiersAsync(
            IReadOnlyCollection<string> normalizedKeys,
            CancellationToken ct)
        => Task.FromResult<IReadOnlyList<IdentityUser<TProfile>>>(
            Array.Empty<IdentityUser<TProfile>>());
}
