using Microsoft.Extensions.DependencyInjection.Extensions;
using Skopka.Identity;
using Skopka.Identity.Authentication;
using Skopka.Identity.Credentials;

namespace Microsoft.Extensions.DependencyInjection;

public static class IdentityPasswordHasherBuilderExtensions
{
    public static IdentityBuilder<TProfile> UsePbkdf2PasswordHasher<TProfile>(
        this IdentityBuilder<TProfile> builder,
        Action<Pbkdf2PasswordHasherOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var options = new Pbkdf2PasswordHasherOptions();
        configure?.Invoke(options);

        RemovePasswordHasherRegistrations(builder.Services);
        builder.Services.RemoveAll<IPasswordHasher>();
        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();
        builder.Services.TryAddScoped<
            IPasswordCredentialService<TProfile>,
            PasswordCredentialService<TProfile>>();
        AddPasswordAuthentication<TProfile>(builder.Services);

        return builder;
    }

    public static IdentityBuilder<TProfile> UseArgon2idPepperedPasswordHasher<TProfile>(
        this IdentityBuilder<TProfile> builder,
        Action<Argon2idPepperedPasswordHasherOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var options = new Argon2idPepperedPasswordHasherOptions();
        configure?.Invoke(options);

        RemovePasswordHasherRegistrations(builder.Services);
        builder.Services.RemoveAll<IPasswordHasher>();
        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton<IPasswordHasher, Argon2idPepperedPasswordHasher>();
        builder.Services.TryAddScoped<
            IPasswordCredentialService<TProfile>,
            PasswordCredentialService<TProfile>>();
        AddPasswordAuthentication<TProfile>(builder.Services);

        return builder;
    }

    public static IdentityBuilder<TProfile> UseArgon2idPepperedPasswordHasher<TProfile>(
        this IdentityBuilder<TProfile> builder,
        IPasswordPepperProvider pepperProvider,
        Action<Argon2idPepperedPasswordHasherOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(pepperProvider);

        builder.Services.RemoveAll<IPasswordPepperProvider>();
        builder.Services.AddSingleton(pepperProvider);

        return builder.UseArgon2idPepperedPasswordHasher(configure);
    }

    private static void RemovePasswordHasherRegistrations(IServiceCollection services)
    {
        services.RemoveAll<Pbkdf2PasswordHasherOptions>();
        services.RemoveAll<Argon2idPepperedPasswordHasherOptions>();
    }

    private static void AddPasswordAuthentication<TProfile>(
        IServiceCollection services)
    {
        services.TryAddSingleton<
            IPasswordVerificationTimingProtector,
            PasswordVerificationTimingProtector>();
        services.TryAddScoped<
            IPasswordAuthenticationService<TProfile>,
            PasswordAuthenticationService<TProfile>>();
    }
}
