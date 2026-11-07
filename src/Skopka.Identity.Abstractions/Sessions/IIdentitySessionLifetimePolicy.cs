using Skopka.Identity.Users;

namespace Skopka.Identity.Sessions;

/// <summary>Determines the fixed absolute lifetime of a new logical session.</summary>
public interface IIdentitySessionLifetimePolicy<TProfile>
{
    /// <summary>Returns a positive lifetime for the validated user and trusted context.</summary>
    Task<TimeSpan> GetLifetimeAsync(IdentityUser<TProfile> user, IdentitySessionContext? context,
        TimeSpan defaultLifetime, CancellationToken cancellationToken);
}
