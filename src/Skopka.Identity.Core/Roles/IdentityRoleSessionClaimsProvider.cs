using Skopka.Identity.Sessions;
using Skopka.Identity.Users;

namespace Skopka.Identity.Roles;

public sealed class IdentityRoleSessionClaimsProvider<TProfile>(
    IIdentityUserRoleStore<TProfile> userRoleStore)
    : IIdentitySessionClaimsProvider<TProfile>
{
    public async Task<IReadOnlyCollection<IdentitySessionClaim>> GetClaimsAsync(
        IdentityUser<TProfile> user,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(user);

        var roles = await userRoleStore.GetRolesAsync(user.Id, ct);
        return roles
            .Select(role => new IdentitySessionClaim(
                IdentitySessionClaimTypes.Role,
                role.Name))
            .ToArray();
    }
}
