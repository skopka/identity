using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql.EntityFrameworkCore.PostgreSQL.Infrastructure;
using Skopka.Identity;
using Skopka.Identity.Authentication;
using Skopka.Identity.Credentials;
using Skopka.Identity.DeviceAuthorization;
using Skopka.Identity.Ef;
using Skopka.Identity.Ef.PostgreSql;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Registration;
using Skopka.Identity.Roles;
using Skopka.Identity.Roles.Queries;
using Skopka.Identity.Sessions;
using Skopka.Identity.Totp;
using Skopka.Identity.Verification;
using Skopka.Identity.Users.Queries;

namespace Microsoft.Extensions.DependencyInjection;

public static class PostgreSqlIdentityBuilderExtensions
{
    public static IdentityBuilder<TProfile> UsePostgreSql<TProfile>(
        this IdentityBuilder<TProfile> builder,
        string connectionString,
        Action<NpgsqlDbContextOptionsBuilder>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        builder.Services.AddDbContext<PostgreSqlIdentityDbContext<TProfile>>(
            options => options.UseNpgsql(
                connectionString,
                npgsql =>
                {
                    npgsql.MigrationsAssembly(
                        typeof(PostgreSqlIdentityDbContext<>).Assembly.GetName().Name);
                    configure?.Invoke(npgsql);
                }));

        builder.Services.TryAddScoped<IdentityDbContext<TProfile>>(
            provider => provider.GetRequiredService<PostgreSqlIdentityDbContext<TProfile>>());
        builder.Services.TryAddScoped<IIdentityUserStore<TProfile>, EfIdentityUserStore<TProfile>>();
        builder.Services.TryAddScoped<
            IIdentityUserQueryStore<TProfile>,
            EfIdentityUserQueryStore<TProfile>>();
        builder.Services.TryAddScoped<
            IIdentityUserLookupStore<TProfile>,
            EfIdentityUserStore<TProfile>>();
        builder.Services.TryAddScoped<
            IExternalLoginStore<TProfile>,
            EfExternalLoginStore<TProfile>>();
        builder.Services.TryAddScoped<
            IIdentityRegistrationStore<TProfile>,
            EfIdentityRegistrationStore<TProfile>>();
        builder.Services.TryAddScoped<
            IPasswordCredentialStore<TProfile>,
            EfPasswordCredentialStore<TProfile>>();
        builder.Services.TryAddScoped<
            IVerificationChallengeStore<TProfile>,
            EfVerificationChallengeStore<TProfile>>();
        builder.Services.TryAddScoped<
            ITotpFactorStore<TProfile>,
            EfTotpFactorStore<TProfile>>();
        builder.Services.TryAddScoped<
            IRateLimitBucketStore<TProfile>,
            EfRateLimitBucketStore<TProfile>>();
        builder.Services.TryAddScoped<
            IIdentityRefreshSessionStore<TProfile>,
            EfIdentitySessionStore<TProfile>>();
        builder.Services.TryAddScoped<
            IIdentitySessionStore<TProfile>,
            EfIdentitySessionStore<TProfile>>();
        builder.Services.TryAddScoped<
            IDeviceAuthorizationRequestStore<TProfile>,
            EfDeviceAuthorizationRequestStore<TProfile>>();
        builder.Services.TryAddScoped<
            IIdentityRoleStore<TProfile>,
            EfIdentityRoleStore<TProfile>>();
        builder.Services.TryAddScoped<
            IIdentityRoleQueryStore<TProfile>,
            EfIdentityRoleQueryStore<TProfile>>();
        builder.Services.TryAddScoped<
            IIdentityUserRoleStore<TProfile>,
            EfIdentityUserRoleStore<TProfile>>();
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IEfIdentityExceptionMapper, PostgreSqlIdentityExceptionMapper>());

        return builder;
    }
}
