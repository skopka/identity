using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Skopka.Identity.Authentication;
using Skopka.Identity.Credentials;
using Skopka.Identity.DeviceAuthorization;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.Metrics;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Registration;
using Skopka.Identity.Roles;
using Skopka.Identity.Roles.Queries;
using Skopka.Identity.Security;
using Skopka.Identity.SecurityEvents;
using Skopka.Identity.Sessions;
using Skopka.Identity.SignInMethods;
using Skopka.Identity.StepUp;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Queries;
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
            .AddRoles()
            .AddStepUpAuthorization<TestStepUpPolicyProvider>()
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
        Assert.IsType<IdentityUserQueryService<TestProfile>>(
            scopedProvider.GetRequiredService<
                IIdentityUserQueryService<TestProfile>>());
        Assert.IsType<EfIdentityUserQueryStore<TestProfile>>(
            scopedProvider.GetRequiredService<
                IIdentityUserQueryStore<TestProfile>>());
        Assert.IsType<ExternalLoginService<TestProfile>>(
            scopedProvider.GetRequiredService<
                IExternalLoginService<TestProfile>>());
        Assert.IsType<IdentitySignInMethodQueryService<TestProfile>>(
            scopedProvider.GetRequiredService<
                IIdentitySignInMethodQueryService<TestProfile>>());
        Assert.IsType<EfExternalLoginStore<TestProfile>>(
            scopedProvider.GetRequiredService<
                IExternalLoginStore<TestProfile>>());
        Assert.IsType<IdentityRegistrationService<TestProfile>>(
            scopedProvider.GetRequiredService<
                IIdentityRegistrationService<TestProfile>>());
        Assert.IsType<EfIdentityRegistrationStore<TestProfile>>(
            scopedProvider.GetRequiredService<
                IIdentityRegistrationStore<TestProfile>>());
        Assert.IsType<NoopIdentitySecurityEventObserver>(
            scopedProvider.GetRequiredService<
                IIdentitySecurityEventObserver>());
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
        Assert.IsType<EfDeviceAuthorizationRequestStore<TestProfile>>(
            scopedProvider.GetRequiredService<
                IDeviceAuthorizationRequestStore<TestProfile>>());
        Assert.IsType<IdentityVerificationService<TestProfile>>(
            scopedProvider.GetRequiredService<
                IIdentityVerificationService<TestProfile>>());
        Assert.IsType<EfRateLimitBucketStore<TestProfile>>(
            scopedProvider.GetRequiredService<
                IRateLimitBucketStore<TestProfile>>());
        Assert.IsType<EfIdentitySessionStore<TestProfile>>(
            scopedProvider.GetRequiredService<
                IIdentityRefreshSessionStore<TestProfile>>());
        Assert.IsType<EfIdentitySessionStore<TestProfile>>(
            scopedProvider.GetRequiredService<
                IIdentitySessionStore<TestProfile>>());
        Assert.IsType<IdentitySessionRegistry<TestProfile>>(
            scopedProvider.GetRequiredService<
                IIdentitySessionRegistry<TestProfile>>());
        Assert.IsType<DefaultIdentityRoleNormalizer>(
            scopedProvider.GetRequiredService<IIdentityRoleNormalizer>());
        Assert.IsType<IdentityRoleService<TestProfile>>(
            scopedProvider.GetRequiredService<
                IIdentityRoleService<TestProfile>>());
        Assert.IsType<EfIdentityRoleStore<TestProfile>>(
            scopedProvider.GetRequiredService<
                IIdentityRoleStore<TestProfile>>());
        Assert.IsType<IdentityRoleQueryService<TestProfile>>(
            scopedProvider.GetRequiredService<
                IIdentityRoleQueryService<TestProfile>>());
        Assert.IsType<EfIdentityRoleQueryStore<TestProfile>>(
            scopedProvider.GetRequiredService<
                IIdentityRoleQueryStore<TestProfile>>());
        Assert.IsType<EfIdentityUserRoleStore<TestProfile>>(
            scopedProvider.GetRequiredService<
                IIdentityUserRoleStore<TestProfile>>());
        Assert.Contains(
            scopedProvider.GetServices<
                IIdentitySessionClaimsProvider<TestProfile>>(),
            claimsProvider =>
                claimsProvider is IdentityRoleSessionClaimsProvider<TestProfile>);
        Assert.IsType<TestStepUpPolicyProvider>(
            scopedProvider.GetRequiredService<
                IStepUpPolicyProvider<TestProfile>>());
        Assert.IsType<IdentityStepUpService<TestProfile>>(
            scopedProvider.GetRequiredService<
                IIdentityStepUpService<TestProfile>>());

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
        var roleMigration = Assert.Single(
            providerContext.Database.GetMigrations(),
            name => name.EndsWith(
                "_AddIdentityRoles",
                StringComparison.Ordinal));
        var externalLoginMigration = Assert.Single(
            providerContext.Database.GetMigrations(),
            name => name.EndsWith(
                "_AddExternalLoginLifecycleAndSessionMetadata",
                StringComparison.Ordinal));
        var rateLimitRotationMigration = Assert.Single(
            providerContext.Database.GetMigrations(),
            name => name.EndsWith(
                "_AddRateLimitPartitionVersions",
                StringComparison.Ordinal));
        var loginIdentifierMigration = Assert.Single(
            providerContext.Database.GetMigrations(),
            name => name.EndsWith(
                "_AddLoginIdentifierRegistry",
                StringComparison.Ordinal));
        var verificationSupersedeMigration = Assert.Single(
            providerContext.Database.GetMigrations(),
            name => name.EndsWith(
                "_SupersedeVerificationChallenges",
                StringComparison.Ordinal));
        Assert.Single(
            providerContext.Database.GetMigrations(),
            name => name.EndsWith(
                "_AddLogicalIdentitySessions",
                StringComparison.Ordinal));
        Assert.Single(
            providerContext.Database.GetMigrations(),
            name => name.EndsWith(
                "_AddDeviceAuthorization",
                StringComparison.Ordinal));
        Assert.Single(
            providerContext.Database.GetMigrations(),
            name => name.EndsWith(
                "_AddWebAuthnCredentials",
                StringComparison.Ordinal));
        Assert.False(providerContext.Database.HasPendingModelChanges());

        var script = providerContext.GetService<IMigrator>().GenerateScript(
            fromMigration: null,
            toMigration: verificationSupersedeMigration);

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
            "partition_version",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "DEFAULT 'legacy'",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "CREATE TABLE identity_login_identifiers",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "INSERT INTO identity_login_identifiers",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "REGEXP_REPLACE",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "ux_identity_login_identifiers_active_normalized_key",
            script,
            StringComparison.Ordinal);
        Assert.Contains("intent_hash", script, StringComparison.Ordinal);
        Assert.Contains("ROW_NUMBER()", script, StringComparison.Ordinal);
        Assert.Contains(
            "ux_verification_challenges_active_intent",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "CREATE TABLE identity_refresh_sessions",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "CREATE TABLE identity_roles",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "CREATE TABLE identity_user_roles",
            script,
            StringComparison.Ordinal);
        Assert.Contains("client_name", script, StringComparison.Ordinal);
        Assert.Contains("device_name", script, StringComparison.Ordinal);
        Assert.Contains(
            "pk_user_external_logins",
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

    private sealed class TestStepUpPolicyProvider
        : IStepUpPolicyProvider<TestProfile>
    {
        public Task<StepUpRequirement?> GetRequirementAsync(
            StepUpAuthorizationContext context,
            CancellationToken ct)
            => Task.FromResult<StepUpRequirement?>(null);
    }
}
