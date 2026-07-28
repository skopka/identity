using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Skopka.Identity.Roles;
using Skopka.Identity.Sessions;

namespace Skopka.Identity;

public sealed class IdentityBuilder<TProfile>
{
    internal IdentityBuilder(IServiceCollection services)
    {
        Services = services;
    }

    public IServiceCollection Services { get; }

    public IdentityBuilder<TProfile> AddRoles()
    {
        Services.TryAddSingleton<
            IIdentityRoleNormalizer,
            DefaultIdentityRoleNormalizer>();
        Services.TryAddScoped<
            IIdentityRoleService<TProfile>,
            IdentityRoleService<TProfile>>();
        Services.TryAddEnumerable(
            ServiceDescriptor.Scoped<
                IIdentitySessionClaimsProvider<TProfile>,
                IdentityRoleSessionClaimsProvider<TProfile>>());

        return this;
    }

    public IdentityBuilder<TProfile>
        AddSessionClaimsProvider<TProvider>()
        where TProvider : class, IIdentitySessionClaimsProvider<TProfile>
    {
        Services.TryAddEnumerable(
            ServiceDescriptor.Scoped<
                IIdentitySessionClaimsProvider<TProfile>,
                TProvider>());

        return this;
    }
}
