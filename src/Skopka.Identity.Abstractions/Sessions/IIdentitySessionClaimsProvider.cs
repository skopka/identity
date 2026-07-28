using Skopka.Identity.Users;

namespace Skopka.Identity.Sessions;

public interface IIdentitySessionClaimsProvider<TProfile>
{
    Task<IReadOnlyCollection<IdentitySessionClaim>> GetClaimsAsync(
        IdentityUser<TProfile> user,
        CancellationToken ct);
}
