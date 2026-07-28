using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql.EntityFrameworkCore.PostgreSQL.Infrastructure;
using Skopka.Identity;
using Skopka.Identity.Authentication;
using Skopka.Identity.Credentials;
using Skopka.Identity.Ef;
using Skopka.Identity.Ef.PostgreSql;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Roles;
using Skopka.Identity.Sessions;
using Skopka.Identity.Verification;

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
            IIdentityUserLookupStore<TProfile>,
            EfIdentityUserStore<TProfile>>();
        builder.Services.TryAddScoped<
            IPasswordCredentialStore<TProfile>,
            EfPasswordCredentialStore<TProfile>>();
        builder.Services.TryAddScoped<
            IVerificationChallengeStore<TProfile>,
            EfVerificationChallengeStore<TProfile>>();
        builder.Services.TryAddScoped<
            IRateLimitBucketStore<TProfile>,
            EfRateLimitBucketStore<TProfile>>();
        builder.Services.TryAddScoped<
            IIdentityRefreshSessionStore<TProfile>,
            EfIdentityRefreshSessionStore<TProfile>>();
        builder.Services.TryAddScoped<
            IIdentityRoleStore<TProfile>,
            EfIdentityRoleStore<TProfile>>();
        builder.Services.TryAddScoped<
            IIdentityUserRoleStore<TProfile>,
            EfIdentityUserRoleStore<TProfile>>();
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IEfIdentityExceptionMapper, PostgreSqlIdentityExceptionMapper>());

        return builder;
    }
}
