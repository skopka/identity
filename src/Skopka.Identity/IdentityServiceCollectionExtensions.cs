using Microsoft.Extensions.DependencyInjection.Extensions;
using Skopka.Identity;
using Skopka.Identity.Metrics;
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
        services.TryAddScoped<IIdentityUserService<TProfile>, IdentityUserService<TProfile>>();

        return new IdentityBuilder<TProfile>(services);
    }
}
