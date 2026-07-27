using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Skopka.Identity.Authentication;
using Skopka.Identity.Credentials;
using Skopka.Identity.Metrics;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Security;
using Skopka.Identity.Sessions;
using Skopka.Identity.Users;
using Skopka.Identity.Verification;
using Xunit;

namespace Skopka.Identity.Ef.PostgreSql.Tests;

public sealed class PostgreSqlIdentityRegistrationTests
{
    [Fact]
    public void RegistersCompleteIdentityServiceGraph()
    {
        var services = new ServiceCollection();

        services
            .AddSkopkaIdentity<TestProfile>()
            .UsePostgreSql("Host=localhost;Database=skopka_identity_di_tests");

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var scopedProvider = scope.ServiceProvider;

        Assert.IsType<DefaultIdentityNormalizer>(
            scopedProvider.GetRequiredService<IIdentityNormalizer>());
        Assert.IsType<DefaultUserOperationPolicy>(
            scopedProvider.GetRequiredService<IUserOperationPolicy>());
        Assert.IsType<IdentityMetrics>(
            scopedProvider.GetRequiredService<IIdentityMetrics>());
        Assert.IsType<IdentityUserService<TestProfile>>(
            scopedProvider.GetRequiredService<IIdentityUserService<TestProfile>>());
        Assert.IsType<DefaultSecurityStampGenerator>(
            scopedProvider.GetRequiredService<ISecurityStampGenerator>());
        Assert.IsType<SecurityStampService<TestProfile>>(
            scopedProvider.GetRequiredService<ISecurityStampService<TestProfile>>());
        Assert.IsType<EfIdentityUserStore<TestProfile>>(
            scopedProvider.GetRequiredService<IIdentityUserStore<TestProfile>>());
        Assert.IsType<EfIdentityUserStore<TestProfile>>(
            scopedProvider.GetRequiredService<IIdentityUserLookupStore<TestProfile>>());
        Assert.IsType<EfPasswordCredentialStore<TestProfile>>(
            scopedProvider.GetRequiredService<IPasswordCredentialStore<TestProfile>>());
        Assert.IsType<EfVerificationChallengeStore<TestProfile>>(
            scopedProvider.GetRequiredService<
                IVerificationChallengeStore<TestProfile>>());
        Assert.IsType<IdentityVerificationService<TestProfile>>(
            scopedProvider.GetRequiredService<
                IIdentityVerificationService<TestProfile>>());
        Assert.IsType<EfRateLimitBucketStore<TestProfile>>(
            scopedProvider.GetRequiredService<
                IRateLimitBucketStore<TestProfile>>());
        Assert.IsType<EfIdentityRefreshSessionStore<TestProfile>>(
            scopedProvider.GetRequiredService<
                IIdentityRefreshSessionStore<TestProfile>>());

        var providerContext = scopedProvider.GetRequiredService<PostgreSqlIdentityDbContext<TestProfile>>();
        var storeContext = scopedProvider.GetRequiredService<IdentityDbContext<TestProfile>>();

        Assert.Same(providerContext, storeContext);
        Assert.Contains(
            scopedProvider.GetServices<IEfIdentityExceptionMapper>(),
            mapper => mapper is PostgreSqlIdentityExceptionMapper);

        Assert.Single(
            providerContext.Database.GetMigrations(),
            name => name.EndsWith("_InitialIdentitySchema", StringComparison.Ordinal));
        var securityStampMigration = Assert.Single(
            providerContext.Database.GetMigrations(),
            name => name.EndsWith("_AddSecurityStamp", StringComparison.Ordinal));
        var verificationMigration = Assert.Single(
            providerContext.Database.GetMigrations(),
            name => name.EndsWith(
                "_AddVerificationChallenges",
                StringComparison.Ordinal));
        var rateLimitMigration = Assert.Single(
            providerContext.Database.GetMigrations(),
            name => name.EndsWith(
                "_AddIdentityRateLimitBuckets",
                StringComparison.Ordinal));
        var refreshSessionMigration = Assert.Single(
            providerContext.Database.GetMigrations(),
            name => name.EndsWith(
                "_AddIdentityRefreshSessions",
                StringComparison.Ordinal));
        Assert.False(providerContext.Database.HasPendingModelChanges());

        var script = providerContext.GetService<IMigrator>().GenerateScript(
            fromMigration: null,
            toMigration: refreshSessionMigration);

        Assert.Contains("CREATE TABLE auth_users", script, StringComparison.Ordinal);
        Assert.Contains("CREATE TABLE user_profiles", script, StringComparison.Ordinal);
        Assert.Contains("jsonb", script, StringComparison.Ordinal);
        Assert.Contains("ux_auth_users_normalized_email", script, StringComparison.Ordinal);
        Assert.Contains("security_stamp", script, StringComparison.Ordinal);
        Assert.Contains("gen_random_uuid()", script, StringComparison.Ordinal);
        Assert.Contains(
            "CREATE TABLE verification_challenges",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "CREATE TABLE identity_rate_limit_buckets",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "CREATE TABLE identity_refresh_sessions",
            script,
            StringComparison.Ordinal);
    }

    [Fact]
    public void PreservesConsumerOverridesRegisteredFirst()
    {
        var services = new ServiceCollection();
        var normalizer = new TestNormalizer();
        var securityStampGenerator = new TestSecurityStampGenerator();
        services.AddSingleton<IIdentityNormalizer>(normalizer);
        services.AddSingleton<ISecurityStampGenerator>(securityStampGenerator);

        services.AddSkopkaIdentity<TestProfile>();

        using var provider = services.BuildServiceProvider();

        Assert.Same(normalizer, provider.GetRequiredService<IIdentityNormalizer>());
        Assert.Same(
            securityStampGenerator,
            provider.GetRequiredService<ISecurityStampGenerator>());
    }

    public sealed record TestProfile(string DisplayName);

    private sealed class TestNormalizer : IIdentityNormalizer
    {
        public string? NormalizeUserName(string? value) => value;
        public string? NormalizeEmail(string? value) => value;
        public string? NormalizePhone(string? value) => value;
    }

    private sealed class TestSecurityStampGenerator : ISecurityStampGenerator
    {
        public string Generate() => "TEST-STAMP";
    }
}
