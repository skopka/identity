using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql.EntityFrameworkCore.PostgreSQL.Infrastructure;
using Skopka.Identity;
using Skopka.Identity.Ef;
using Skopka.Identity.Ef.PostgreSql;

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
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IEfIdentityExceptionMapper, PostgreSqlIdentityExceptionMapper>());

        return builder;
    }
}
