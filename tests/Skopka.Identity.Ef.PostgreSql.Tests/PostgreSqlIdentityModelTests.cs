using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Authentication;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Roles;
using Skopka.Identity.Sessions;
using Skopka.Identity.Verification;
using Xunit;

namespace Skopka.Identity.Ef.PostgreSql.Tests;

public sealed class PostgreSqlIdentityModelTests
{
    [Fact]
    public void ModelUsesJsonProfileAndFilteredHandleIndexes()
    {
        var options = new DbContextOptionsBuilder<PostgreSqlIdentityDbContext<TestProfile>>()
            .UseNpgsql("Host=localhost;Database=skopka_identity_model_tests")
            .Options;

        using var context = new PostgreSqlIdentityDbContext<TestProfile>(options);

        var profileType = context.Model.FindEntityType(typeof(UserProfileEntity<TestProfile>));
        var profileProperty = profileType?.FindProperty(nameof(UserProfileEntity<TestProfile>.Profile));

        Assert.NotNull(profileProperty);
        Assert.Equal("jsonb", profileProperty.GetColumnType());

        var userType = context.Model.FindEntityType(typeof(AuthUserEntity));
        Assert.NotNull(userType);

        var securityStamp = userType.FindProperty(nameof(AuthUserEntity.SecurityStamp));
        Assert.NotNull(securityStamp);
        Assert.False(securityStamp.IsNullable);
        Assert.Equal(64, securityStamp.GetMaxLength());

        AssertUniqueFilteredIndex(
            userType,
            "ux_auth_users_normalized_user_name",
            "deleted_at IS NULL AND normalized_user_name IS NOT NULL");
        AssertUniqueFilteredIndex(
            userType,
            "ux_auth_users_normalized_email",
            "deleted_at IS NULL AND normalized_email IS NOT NULL");
        AssertUniqueFilteredIndex(
            userType,
            "ux_auth_users_normalized_phone",
            "deleted_at IS NULL AND normalized_phone IS NOT NULL");

        var loginIdentifierType = context.Model.FindEntityType(
            typeof(LoginIdentifierEntity));
        Assert.NotNull(loginIdentifierType);
        Assert.Equal(
            2,
            loginIdentifierType.FindPrimaryKey()!.Properties.Count);
        Assert.Equal(
            IdentityLoginLimits.MaximumLoginLength,
            loginIdentifierType
                .FindProperty(nameof(LoginIdentifierEntity.NormalizedKey))!
                .GetMaxLength());
        AssertUniqueFilteredIndex(
            loginIdentifierType,
            "ux_identity_login_identifiers_active_normalized_key",
            "is_active = TRUE");

        var challengeType = context.Model.FindEntityType(
            typeof(VerificationChallengeEntity));
        Assert.NotNull(challengeType);
        Assert.True(
            challengeType
                .FindProperty(nameof(VerificationChallengeEntity.Version))!
                .IsConcurrencyToken);
        Assert.Equal(
            VerificationLimits.MaximumBindingLength,
            challengeType
                .FindProperty(nameof(VerificationChallengeEntity.Binding))!
                .GetMaxLength());
        Assert.Equal(
            64,
            challengeType
                .FindProperty(nameof(VerificationChallengeEntity.ProofHash))!
                .GetMaxLength());
        var intentHash = challengeType.FindProperty(
            nameof(VerificationChallengeEntity.IntentHash));
        Assert.NotNull(intentHash);
        Assert.False(intentHash.IsNullable);
        Assert.Equal(64, intentHash.GetMaxLength());
        AssertUniqueFilteredIndex(
            challengeType,
            "ux_verification_challenges_active_intent",
            "state IN (0, 1)");

        var rateLimitType = context.Model.FindEntityType(
            typeof(RateLimitBucketEntity));
        Assert.NotNull(rateLimitType);
        Assert.True(
            rateLimitType
                .FindProperty(nameof(RateLimitBucketEntity.Version))!
                .IsConcurrencyToken);
        Assert.Equal(
            RateLimitLimits.KeyHashLength,
            rateLimitType
                .FindProperty(nameof(RateLimitBucketEntity.KeyHash))!
                .GetMaxLength());
        Assert.Equal(
            RateLimitLimits.MaximumPartitionVersionLength,
            rateLimitType
                .FindProperty(nameof(
                    RateLimitBucketEntity.PartitionVersion))!
                .GetMaxLength());
        Assert.Equal(
            3,
            rateLimitType.FindPrimaryKey()!.Properties.Count);

        var refreshSessionType = context.Model.FindEntityType(
            typeof(RefreshSessionEntity));
        Assert.NotNull(refreshSessionType);
        Assert.True(
            refreshSessionType
                .FindProperty(nameof(RefreshSessionEntity.Version))!
                .IsConcurrencyToken);
        Assert.Equal(
            SessionLimits.TokenHashLength,
            refreshSessionType
                .FindProperty(nameof(RefreshSessionEntity.TokenHash))!
                .GetMaxLength());
        Assert.Equal(
            SessionLimits.SecurityStampLength,
            refreshSessionType
                .FindProperty(nameof(RefreshSessionEntity.SecurityStamp))!
                .GetMaxLength());
        Assert.Equal(
            SessionLimits.MaximumClientNameLength,
            refreshSessionType
                .FindProperty(nameof(RefreshSessionEntity.ClientName))!
                .GetMaxLength());
        Assert.Equal(
            SessionLimits.MaximumDeviceNameLength,
            refreshSessionType
                .FindProperty(nameof(RefreshSessionEntity.DeviceName))!
                .GetMaxLength());

        var externalLoginType = context.Model.FindEntityType(
            typeof(UserExternalLoginEntity));
        Assert.NotNull(externalLoginType);
        Assert.Equal(
            ExternalLoginLimits.MaximumProviderLength,
            externalLoginType
                .FindProperty(nameof(UserExternalLoginEntity.Provider))!
                .GetMaxLength());
        Assert.Equal(
            ExternalLoginLimits.MaximumSubjectLength,
            externalLoginType
                .FindProperty(nameof(UserExternalLoginEntity.Subject))!
                .GetMaxLength());
        Assert.Equal(
            "pk_user_external_logins",
            externalLoginType.FindPrimaryKey()!.GetName());

        var roleType = context.Model.FindEntityType(typeof(RoleEntity));
        Assert.NotNull(roleType);
        Assert.True(
            roleType
                .FindProperty(nameof(RoleEntity.Version))!
                .IsConcurrencyToken);
        Assert.Equal(
            IdentityRoleLimits.MaximumNameLength,
            roleType
                .FindProperty(nameof(RoleEntity.NormalizedName))!
                .GetMaxLength());
        AssertUniqueIndex(
            roleType,
            "ux_identity_roles_normalized_name");

        var membershipType = context.Model.FindEntityType(
            typeof(UserRoleEntity));
        Assert.NotNull(membershipType);
        Assert.Equal(2, membershipType.FindPrimaryKey()!.Properties.Count);
    }

    private static void AssertUniqueFilteredIndex(
        Microsoft.EntityFrameworkCore.Metadata.IReadOnlyEntityType entityType,
        string databaseName,
        string filter)
    {
        var index = Assert.Single(
            entityType.GetIndexes(),
            candidate => candidate.GetDatabaseName() == databaseName);

        Assert.True(index.IsUnique);
        Assert.Equal(filter, index.GetFilter());
    }

    private static void AssertUniqueIndex(
        Microsoft.EntityFrameworkCore.Metadata.IReadOnlyEntityType entityType,
        string databaseName)
    {
        var index = Assert.Single(
            entityType.GetIndexes(),
            candidate => candidate.GetDatabaseName() == databaseName);

        Assert.True(index.IsUnique);
        Assert.Null(index.GetFilter());
    }

    public sealed record TestProfile(string DisplayName);
}
