using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Skopka.Identity;
using Skopka.Identity.Authentication;
using Skopka.Identity.Credentials;
using Skopka.Identity.Ef;
using Skopka.Identity.Ef.Sqlite;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Registration;
using Skopka.Identity.Roles;
using Skopka.Identity.Roles.Queries;
using Skopka.Identity.Sessions;
using Skopka.Identity.Users.Queries;
using Skopka.Identity.Verification;
using Skopka.Identity.Totp;

namespace Microsoft.Extensions.DependencyInjection;

public static class SqliteIdentityBuilderExtensions
{
    public static IdentityBuilder<TProfile> UseSqlite<TProfile>(
        this IdentityBuilder<TProfile> builder,
        string connectionString,
        Action<SqliteDbContextOptionsBuilder>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        builder.Services.AddDbContext<SqliteIdentityDbContext<TProfile>>(
            options => options.UseSqlite(
                connectionString,
                sqlite => ConfigureProvider(sqlite, configure)));

        return AddStores(builder);
    }

    public static IdentityBuilder<TProfile> UseSqlite<TProfile>(
        this IdentityBuilder<TProfile> builder,
        DbConnection connection,
        bool contextOwnsConnection = false,
        Action<SqliteDbContextOptionsBuilder>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(connection);

        builder.Services.AddDbContext<SqliteIdentityDbContext<TProfile>>(
            options => options.UseSqlite(
                connection,
                contextOwnsConnection,
                sqlite => ConfigureProvider(sqlite, configure)));

        return AddStores(builder);
    }

    private static void ConfigureProvider(
        SqliteDbContextOptionsBuilder sqlite,
        Action<SqliteDbContextOptionsBuilder>? configure)
    {
        sqlite.MigrationsAssembly(
            typeof(SqliteIdentityDbContext<>).Assembly.GetName().Name);
        configure?.Invoke(sqlite);
    }

    private static IdentityBuilder<TProfile> AddStores<TProfile>(
        IdentityBuilder<TProfile> builder)
    {
        builder.Services.TryAddScoped<IdentityDbContext<TProfile>>(
            provider => provider.GetRequiredService<
                SqliteIdentityDbContext<TProfile>>());
        builder.Services.TryAddScoped<
            IIdentityUserStore<TProfile>,
            EfIdentityUserStore<TProfile>>();
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
            IIdentityRoleStore<TProfile>,
            EfIdentityRoleStore<TProfile>>();
        builder.Services.TryAddScoped<
            IIdentityRoleQueryStore<TProfile>,
            EfIdentityRoleQueryStore<TProfile>>();
        builder.Services.TryAddScoped<
            IIdentityUserRoleStore<TProfile>,
            EfIdentityUserRoleStore<TProfile>>();
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IEfIdentityExceptionMapper,
                SqliteIdentityExceptionMapper>());

        return builder;
    }
}
