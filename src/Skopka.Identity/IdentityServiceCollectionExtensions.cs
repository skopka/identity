using Microsoft.Extensions.DependencyInjection.Extensions;
using Skopka.Identity;
using Skopka.Identity.Metrics;
using Skopka.Identity.Security;
using Skopka.Identity.Users;

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
        services.TryAddScoped<IIdentityUserService<TProfile>, IdentityUserService<TProfile>>();
        services.TryAddScoped<
            ISecurityStampService<TProfile>,
            SecurityStampService<TProfile>>();

        return new IdentityBuilder<TProfile>(services);
    }
}
