using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Skopka.Identity;
using Skopka.Identity.Tokens;

namespace Microsoft.Extensions.DependencyInjection;

public static class IdentityActionTokenBuilderExtensions
{
    public static IdentityBuilder<TProfile> UseDataProtectionActionTokens<TProfile>(
        this IdentityBuilder<TProfile> builder,
        Action<IdentityActionTokenOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var options = new IdentityActionTokenOptions();
        configure?.Invoke(options);
        ValidateOptions(options);

        builder.Services.AddDataProtection();
        builder.Services.RemoveAll<IdentityActionTokenOptions>();
        builder.Services.RemoveAll<IIdentityActionTokenProvider>();
        builder.Services.RemoveAll<IIdentityActionTokenIssuer<TProfile>>();
        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton<
            IIdentityActionTokenProvider,
            DataProtectionIdentityActionTokenProvider>();
        builder.Services.AddScoped<
            IIdentityActionTokenIssuer<TProfile>,
            IdentityActionTokenIssuer<TProfile>>();

        return builder;
    }

    private static void ValidateOptions(IdentityActionTokenOptions options)
    {
        ValidateLifetime(
            options.EmailConfirmationLifetime,
            nameof(options.EmailConfirmationLifetime));
        ValidateLifetime(
            options.PhoneConfirmationLifetime,
            nameof(options.PhoneConfirmationLifetime));
        ValidateLifetime(
            options.PasswordResetLifetime,
            nameof(options.PasswordResetLifetime));
    }

    private static void ValidateLifetime(TimeSpan lifetime, string name)
    {
        if (lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                name,
                lifetime,
                "Token lifetime must be positive.");
        }
    }
}
