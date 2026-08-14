using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Skopka.Identity.Authentication;
using Skopka.Identity.Credentials;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Registration;
using Skopka.Identity.Roles;
using Skopka.Identity.Roles.Queries;
using Skopka.Identity.Sessions;
using Skopka.Identity.Totp;
using Skopka.Identity.Users.Queries;
using Skopka.Identity.Verification;
using Xunit;

namespace Skopka.Identity.Ef.Sqlite.Tests;

public sealed class SqliteIdentityRegistrationTests
{
    [Fact]
    public void RegistersCompleteStoreGraph()
    {
        var services = new ServiceCollection();

        services
            .AddSkopkaIdentity<TestProfile>()
            .AddRoles()
            .UseSqlite("Data Source=identity-registration-tests.db");

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var scopedProvider = scope.ServiceProvider;

        Assert.IsType<EfIdentityUserStore<TestProfile>>(
            scopedProvider.GetRequiredService<IIdentityUserStore<TestProfile>>());
        Assert.IsType<EfIdentityUserStore<TestProfile>>(
            scopedProvider.GetRequiredService<IIdentityUserLookupStore<TestProfile>>());
        Assert.IsType<EfIdentityUserQueryStore<TestProfile>>(
            scopedProvider.GetRequiredService<IIdentityUserQueryStore<TestProfile>>());
        Assert.IsType<EfExternalLoginStore<TestProfile>>(
            scopedProvider.GetRequiredService<IExternalLoginStore<TestProfile>>());
        Assert.IsType<EfIdentityRegistrationStore<TestProfile>>(
            scopedProvider.GetRequiredService<IIdentityRegistrationStore<TestProfile>>());
        Assert.IsType<EfPasswordCredentialStore<TestProfile>>(
            scopedProvider.GetRequiredService<IPasswordCredentialStore<TestProfile>>());
        Assert.IsType<EfVerificationChallengeStore<TestProfile>>(
            scopedProvider.GetRequiredService<IVerificationChallengeStore<TestProfile>>());
        Assert.IsType<EfRateLimitBucketStore<TestProfile>>(
            scopedProvider.GetRequiredService<IRateLimitBucketStore<TestProfile>>());
        Assert.IsType<EfIdentitySessionStore<TestProfile>>(
            scopedProvider.GetRequiredService<IIdentityRefreshSessionStore<TestProfile>>());
        Assert.IsType<EfIdentitySessionStore<TestProfile>>(
            scopedProvider.GetRequiredService<IIdentitySessionStore<TestProfile>>());
        Assert.IsType<IdentitySessionRegistry<TestProfile>>(
            scopedProvider.GetRequiredService<IIdentitySessionRegistry<TestProfile>>());
        Assert.IsType<EfIdentityRoleStore<TestProfile>>(
            scopedProvider.GetRequiredService<IIdentityRoleStore<TestProfile>>());
        Assert.IsType<EfIdentityRoleQueryStore<TestProfile>>(
            scopedProvider.GetRequiredService<IIdentityRoleQueryStore<TestProfile>>());
        Assert.IsType<EfIdentityUserRoleStore<TestProfile>>(
            scopedProvider.GetRequiredService<IIdentityUserRoleStore<TestProfile>>());
        Assert.IsType<EfTotpFactorStore<TestProfile>>(
            scopedProvider.GetRequiredService<ITotpFactorStore<TestProfile>>());

        var providerContext = scopedProvider.GetRequiredService<
            SqliteIdentityDbContext<TestProfile>>();
        var storeContext = scopedProvider.GetRequiredService<
            IdentityDbContext<TestProfile>>();
        Assert.Same(providerContext, storeContext);
        Assert.Contains(
            scopedProvider.GetServices<IEfIdentityExceptionMapper>(),
            mapper => mapper is SqliteIdentityExceptionMapper);
        Assert.Equal(3, providerContext.Database.GetMigrations().Count());
    }

    public sealed record TestProfile(string DisplayName);
}
