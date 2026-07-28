using Microsoft.Extensions.DependencyInjection.Extensions;
using Skopka.Identity;
using Skopka.Identity.Verification;

namespace Microsoft.Extensions.DependencyInjection;

public static class IdentityVerificationBuilderExtensions
{
    public static IdentityBuilder<TProfile> UseHmacOneTimeCodes<TProfile>(
        this IdentityBuilder<TProfile> builder,
        string currentKeyId,
        byte[] currentKey,
        Action<HmacOneTimeCodeOptions>? configureCode = null,
        Action<VerificationOptions>? configureVerification = null)
        => builder.UseHmacOneTimeCodes(
            new StaticVerificationCodeKeyProvider(
                currentKeyId,
                currentKey),
            configureCode,
            configureVerification);

    public static IdentityBuilder<TProfile> UseHmacOneTimeCodes<TProfile>(
        this IdentityBuilder<TProfile> builder,
        IVerificationCodeKeyProvider keyProvider,
        Action<HmacOneTimeCodeOptions>? configureCode = null,
        Action<VerificationOptions>? configureVerification = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(keyProvider);

        var codeOptions = new HmacOneTimeCodeOptions();
        configureCode?.Invoke(codeOptions);
        ValidateCodeOptions(codeOptions);

        var verificationOptions = new VerificationOptions();
        configureVerification?.Invoke(verificationOptions);
        ValidateVerificationOptions(verificationOptions);

        builder.Services.RemoveAll<IVerificationCodeKeyProvider>();
        builder.Services.RemoveAll<HmacOneTimeCodeOptions>();
        builder.Services.RemoveAll<VerificationOptions>();
        builder.Services.AddSingleton(keyProvider);
        builder.Services.AddSingleton(codeOptions);
        builder.Services.AddSingleton(verificationOptions);
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IVerificationMethodProvider,
                HmacOneTimeCodeProvider>());

        return builder;
    }

    private static void ValidateCodeOptions(HmacOneTimeCodeOptions options)
    {
        if (options.Digits is < 6 or > 8)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.Digits),
                "OTP codes must contain between 6 and 8 digits.");
        }
    }

    private static void ValidateVerificationOptions(
        VerificationOptions options)
    {
        if (options.ChallengeLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.ChallengeLifetime));
        }

        if (options.ProofLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.ProofLifetime));
        }

        if (options.MaxAttempts <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options.MaxAttempts));
        }

        if (options.MaximumResponseLength <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.MaximumResponseLength));
        }
    }
}
