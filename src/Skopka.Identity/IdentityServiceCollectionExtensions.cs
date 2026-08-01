using Microsoft.Extensions.DependencyInjection.Extensions;
using Skopka.Identity;
using Skopka.Identity.Authentication;
using Skopka.Identity.Credentials;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.Metrics;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Registration;
using Skopka.Identity.Security;
using Skopka.Identity.SecurityEvents;
using Skopka.Identity.Sessions;
using Skopka.Identity.SignInMethods;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Queries;
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
        services.TryAddSingleton<
            IIdentitySecurityEventObserver,
            NoopIdentitySecurityEventObserver>();
        services.TryAddSingleton(new PasswordPolicyOptions());
        services.TryAddSingleton(new IdentityRateLimitOptions());
        services.TryAddSingleton(new IdentitySessionOptions());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IIdentitySessionClaimsProvider<TProfile>,
                DefaultIdentitySessionClaimsProvider<TProfile>>());
        services.TryAddScoped<IIdentityUserService<TProfile>, IdentityUserService<TProfile>>();
        services.TryAddScoped<
            IIdentityUserLookupService<TProfile>,
            IdentityUserLookupService<TProfile>>();
        services.TryAddScoped<
            IIdentityUserQueryService<TProfile>,
            IdentityUserQueryService<TProfile>>();
        services.TryAddScoped<
            IExternalLoginService<TProfile>,
            ExternalLoginService<TProfile>>();
        services.TryAddScoped<
            IIdentitySignInMethodQueryService<TProfile>,
            IdentitySignInMethodQueryService<TProfile>>();
        services.TryAddScoped<
            IIdentityRegistrationService<TProfile>,
            IdentityRegistrationService<TProfile>>();
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
