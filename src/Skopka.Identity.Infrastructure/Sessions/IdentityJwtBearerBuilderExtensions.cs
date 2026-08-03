using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Skopka.Identity;
using Skopka.Identity.Sessions;

namespace Microsoft.Extensions.DependencyInjection;

public static class IdentityJwtBearerBuilderExtensions
{
    public static IdentityBuilder<TProfile>
        UseJwtBearerAuthentication<TProfile>(
            this IdentityBuilder<TProfile> builder,
            Action<IdentityJwtBearerOptions>? configure = null,
            Action<JwtBearerOptions>? configureBearer = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var accessTokenProvider = builder.Services
            .LastOrDefault(descriptor =>
                descriptor.ServiceType
                    == typeof(
                        HmacJwtAccessTokenProviderRegistration))
            ?.ImplementationInstance as
                HmacJwtAccessTokenProviderRegistration
            ?? throw new InvalidOperationException(
                "UseJwtSessions must be called before JWT bearer authentication.");

        var integrationOptions = new IdentityJwtBearerOptions();
        configure?.Invoke(integrationOptions);
        ArgumentException.ThrowIfNullOrWhiteSpace(
            integrationOptions.AuthenticationScheme);

        var authentication = integrationOptions.SetAsDefaultScheme
            ? builder.Services.AddAuthentication(
                integrationOptions.AuthenticationScheme)
            : builder.Services.AddAuthentication();
        builder.Services.AddAuthorization();

        authentication.AddJwtBearer(
            integrationOptions.AuthenticationScheme,
            options =>
            {
                configureBearer?.Invoke(options);
                options.MapInboundClaims = false;
                options.SaveToken = false;
                options.TokenValidationParameters =
                    accessTokenProvider.Provider
                        .CreateTokenValidationParameters();
                options.TokenValidationParameters.NameClaimType =
                    IdentitySessionClaimTypes.Name;
                options.TokenValidationParameters.RoleClaimType =
                    IdentitySessionClaimTypes.Role;

                if (integrationOptions.ValidateSessionOnEveryRequest)
                {
                    var applicationTokenValidated =
                        options.Events.OnTokenValidated;
                    options.Events.OnTokenValidated = async context =>
                    {
                        await applicationTokenValidated(context);
                        if (context.Result?.Failure is not null
                            || context.Result?.None == true)
                        {
                            return;
                        }

                        if (context.SecurityToken is not JsonWebToken jwt)
                        {
                            context.Fail(
                                "The access token format is unsupported.");
                            return;
                        }

                        var sessionService = context.HttpContext
                            .RequestServices
                            .GetRequiredService<
                                IIdentitySessionService<TProfile>>();
                        var result =
                            await sessionService.ValidateAccessTokenAsync(
                                jwt.EncodedToken,
                                context.HttpContext.RequestAborted);
                        if (!result.IsSuccess)
                        {
                            context.Fail(
                                "The identity session is no longer valid.");
                        }
                    };
                }
            });

        return builder;
    }
}
