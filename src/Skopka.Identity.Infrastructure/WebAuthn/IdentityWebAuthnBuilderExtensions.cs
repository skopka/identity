using Microsoft.Extensions.DependencyInjection.Extensions;
using Skopka.Identity;
using Skopka.Identity.Infrastructure.WebAuthn;
using Skopka.Identity.WebAuthn;

namespace Microsoft.Extensions.DependencyInjection;

public static class IdentityWebAuthnBuilderExtensions
{
    /// <summary>
    /// Registers the ceremony verifier. Nothing else: a credential store comes
    /// from the persistence package, and who issues challenges and what a
    /// verified assertion is allowed to do belong to the application.
    /// </summary>
    public static IdentityBuilder<TProfile> UseWebAuthn<TProfile>(
        this IdentityBuilder<TProfile> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<
            IWebAuthnCeremonyVerifier,
            WebAuthnCeremonyVerifier>();
        return builder;
    }
}
