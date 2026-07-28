using Skopka.Identity.Users;

namespace Skopka.Identity.Sessions;

public sealed class DefaultIdentitySessionClaimsProvider<TProfile>
    : IIdentitySessionClaimsProvider<TProfile>
{
    public Task<IReadOnlyCollection<IdentitySessionClaim>> GetClaimsAsync(
        IdentityUser<TProfile> user,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(user);

        var claims = new List<IdentitySessionClaim>(capacity: 6);

        if (user.UserName is not null)
        {
            claims.Add(new IdentitySessionClaim(
                IdentitySessionClaimTypes.Name,
                user.UserName));
            claims.Add(new IdentitySessionClaim(
                IdentitySessionClaimTypes.PreferredUserName,
                user.UserName));
        }

        if (user.Email is not null)
        {
            claims.Add(new IdentitySessionClaim(
                IdentitySessionClaimTypes.Email,
                user.Email));
            claims.Add(new IdentitySessionClaim(
                IdentitySessionClaimTypes.EmailVerified,
                user.EmailConfirmed ? "true" : "false"));
        }

        if (user.Phone is not null)
        {
            claims.Add(new IdentitySessionClaim(
                IdentitySessionClaimTypes.PhoneNumber,
                user.Phone));
            claims.Add(new IdentitySessionClaim(
                IdentitySessionClaimTypes.PhoneNumberVerified,
                user.PhoneConfirmed ? "true" : "false"));
        }

        return Task.FromResult<IReadOnlyCollection<IdentitySessionClaim>>(
            claims);
    }
}
