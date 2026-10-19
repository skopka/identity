using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Skopka.Identity.Credentials;
using Skopka.Identity.PhoneOtp;
using Skopka.Identity.Roles;
using Skopka.Identity.Roles.Queries;
using Skopka.Identity.Sessions;
using Skopka.Identity.StepUp;

namespace Skopka.Identity;

public sealed class IdentityBuilder<TProfile>
{
    internal IdentityBuilder(IServiceCollection services)
    {
        Services = services;
    }

    public IServiceCollection Services { get; }

    public IdentityBuilder<TProfile> ConfigurePasswordPolicy(
        Action<PasswordPolicyOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);

        var options = Services
            .LastOrDefault(
                descriptor => descriptor.ServiceType
                    == typeof(PasswordPolicyOptions))
            ?.ImplementationInstance as PasswordPolicyOptions
            ?? new PasswordPolicyOptions();

        configure(options);
        Services.RemoveAll<PasswordPolicyOptions>();
        Services.AddSingleton(options);

        return this;
    }

    public IdentityBuilder<TProfile> ConfigurePhoneOtp(
        Action<PhoneOtpOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        var options = Services.LastOrDefault(descriptor =>
                descriptor.ServiceType == typeof(PhoneOtpOptions))
            ?.ImplementationInstance as PhoneOtpOptions
            ?? new PhoneOtpOptions();
        configure(options);
        if (options.DailyPhonePermitLimit <= 0
            || options.DailyClientPermitLimit <= 0
            || options.DailyWindow <= TimeSpan.Zero
            || options.AllowedCountryCodes.Any(code =>
                code.Length is < 2 or > 5
                || code[0] != '+'
                || code.Skip(1).Any(character =>
                    character is < '0' or > '9')))
        {
            throw new ArgumentOutOfRangeException(nameof(configure));
        }

        Services.RemoveAll<PhoneOtpOptions>();
        Services.AddSingleton(options);
        return this;
    }

    public IdentityBuilder<TProfile> AddPasswordValidator<TValidator>()
        where TValidator : class, IPasswordValidator<TProfile>
    {
        Services.TryAddEnumerable(
            ServiceDescriptor.Scoped<
                IPasswordValidator<TProfile>,
                TValidator>());

        return this;
    }

    public IdentityBuilder<TProfile> AddRoles()
    {
        Services.TryAddSingleton<
            IIdentityRoleNormalizer,
            DefaultIdentityRoleNormalizer>();
        Services.TryAddScoped<
            IIdentityRoleService<TProfile>,
            IdentityRoleService<TProfile>>();
        Services.TryAddScoped<
            IIdentityRoleQueryService<TProfile>,
            IdentityRoleQueryService<TProfile>>();
        Services.TryAddEnumerable(
            ServiceDescriptor.Scoped<
                IIdentitySessionClaimsProvider<TProfile>,
                IdentityRoleSessionClaimsProvider<TProfile>>());

        return this;
    }

    public IdentityBuilder<TProfile>
        AddStepUpAuthorization<TPolicyProvider>()
        where TPolicyProvider : class, IStepUpPolicyProvider<TProfile>
    {
        Services.TryAddScoped<
            IStepUpPolicyProvider<TProfile>,
            TPolicyProvider>();
        Services.TryAddScoped<
            IIdentityStepUpService<TProfile>,
            IdentityStepUpService<TProfile>>();

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
