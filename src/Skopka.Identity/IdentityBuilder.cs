using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Skopka.Identity.Sessions;

namespace Skopka.Identity;

public sealed class IdentityBuilder<TProfile>
{
    internal IdentityBuilder(IServiceCollection services)
    {
        Services = services;
    }

    public IServiceCollection Services { get; }

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
