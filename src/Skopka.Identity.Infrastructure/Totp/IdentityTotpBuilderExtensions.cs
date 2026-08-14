using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Skopka.Identity;
using Skopka.Identity.Infrastructure.Totp;
using Skopka.Identity.Totp;
using Skopka.Identity.Verification;

namespace Microsoft.Extensions.DependencyInjection;

public static class IdentityTotpBuilderExtensions
{
    public static IdentityBuilder<TProfile> UseDataProtectionTotp<TProfile>(
        this IdentityBuilder<TProfile> builder,
        Action<TotpOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var options = new TotpOptions();
        configure?.Invoke(options);
        Validate(options);

        builder.Services.AddDataProtection();
        builder.Services.RemoveAll<TotpOptions>();
        builder.Services.AddSingleton(options);
        builder.Services.TryAddSingleton<
            ITotpCodeProvider,
            Rfc6238TotpCodeProvider>();
        builder.Services.TryAddSingleton<
            ITotpSecretProtector,
            DataProtectionTotpSecretProtector>();
        builder.Services.TryAddScoped<
            IIdentityTotpService<TProfile>,
            IdentityTotpService<TProfile>>();
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Scoped<
                IVerificationMethodProvider,
                TotpVerificationMethodProvider<TProfile>>());

        return builder;
    }

    private static void Validate(TotpOptions options)
    {
        if (options.EnrollmentLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.EnrollmentLifetime));
        }

        if (options.RecoveryCodeCount is < 1 or > 20)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.RecoveryCodeCount),
                "Between one and twenty recovery codes must be generated.");
        }
    }
}
