using Microsoft.Extensions.DependencyInjection.Extensions;
using Skopka.Identity;
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
}
