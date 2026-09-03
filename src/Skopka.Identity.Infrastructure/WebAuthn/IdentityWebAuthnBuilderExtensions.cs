using Microsoft.Extensions.DependencyInjection.Extensions;
using Skopka.Identity;
using Skopka.Identity.Infrastructure.WebAuthn;
using Skopka.Identity.WebAuthn;

namespace Microsoft.Extensions.DependencyInjection;

public static class IdentityWebAuthnBuilderExtensions
{
    /// <summary>
    /// Registers the credential lifecycle and the ceremony verifier. The
    /// credential store comes from the persistence package; who issues
    /// challenges and what a verified assertion is then allowed to do belong to
    /// the host.
    /// </summary>
    public static IdentityBuilder<TProfile> UseWebAuthn<TProfile>(
        this IdentityBuilder<TProfile> builder,
        Action<WebAuthnOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var options = new WebAuthnOptions();
        configure?.Invoke(options);
        Validate(options);

        builder.Services.RemoveAll<WebAuthnOptions>();
        builder.Services.AddSingleton(options);
        builder.Services.TryAddSingleton<
            IWebAuthnCeremonyVerifier,
            WebAuthnCeremonyVerifier>();
        builder.Services.TryAddScoped<
            IIdentityWebAuthnService<TProfile>,
            IdentityWebAuthnService<TProfile>>();
        return builder;
    }

    private static void Validate(WebAuthnOptions options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.RelyingPartyId);
        options.RelyingPartyId = options.RelyingPartyId.Trim();
        if (options.Origins.Count == 0)
        {
            throw new ArgumentException(
                "At least one origin must be allowed: an origin nobody serves "
                + "is a ceremony nobody can complete.",
                nameof(options));
        }

        foreach (var origin in options.Origins)
        {
            if (!Uri.TryCreate(origin, UriKind.Absolute, out var parsed)
                || parsed.GetLeftPart(UriPartial.Authority) != origin)
            {
                throw new ArgumentException(
                    $"'{origin}' is not an origin: scheme and authority only, "
                    + "with no trailing slash, because that is the form a "
                    + "browser reports and the comparison is exact.",
                    nameof(options));
            }
        }

        if (options.MaximumCredentialsPerUser is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options),
                "Between one and a hundred credentials may be registered.");
        }
    }
}
