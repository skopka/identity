using Microsoft.Extensions.DependencyInjection.Extensions;
using Skopka.Identity;
using Skopka.Identity.Credentials;
using Skopka.Identity.Metrics;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Security;
using Skopka.Identity.Sessions;
using Skopka.Identity.Users;
using Skopka.Identity.Verification;

namespace Microsoft.Extensions.DependencyInjection;

public static class IdentityServiceCollectionExtensions
{
    public static IdentityBuilder<TProfile> AddSkopkaIdentity<TProfile>(
        this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<IIdentityNormalizer, DefaultIdentityNormalizer>();
        services.TryAddSingleton<IUserOperationPolicy, DefaultUserOperationPolicy>();
        services.TryAddSingleton<IIdentityMetrics, IdentityMetrics>();
        services.TryAddSingleton<ISecurityStampGenerator, DefaultSecurityStampGenerator>();
        services.TryAddSingleton(new PasswordPolicyOptions());
        services.TryAddSingleton(new IdentityRateLimitOptions());
        services.TryAddSingleton(new IdentitySessionOptions());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IIdentitySessionClaimsProvider<TProfile>,
                DefaultIdentitySessionClaimsProvider<TProfile>>());
        services.TryAddScoped<IIdentityUserService<TProfile>, IdentityUserService<TProfile>>();
        services.TryAddScoped<
            ISecurityStampService<TProfile>,
            SecurityStampService<TProfile>>();
        services.TryAddSingleton(new VerificationOptions());
        services.TryAddScoped<
            IIdentityVerificationService<TProfile>,
            IdentityVerificationService<TProfile>>();

        return new IdentityBuilder<TProfile>(services);
    }
}
