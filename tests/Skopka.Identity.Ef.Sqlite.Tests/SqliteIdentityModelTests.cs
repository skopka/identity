using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using Skopka.Identity.Ef.Entities;
using Xunit;

namespace Skopka.Identity.Ef.Sqlite.Tests;

public sealed class SqliteIdentityModelTests
{
    [Fact]
    public void ModelUsesTextJsonIntegerTimestampsAndFilteredIndexes()
    {
        var options = new DbContextOptionsBuilder<
                SqliteIdentityDbContext<TestProfile>>()
            .UseSqlite("Data Source=:memory:")
            .Options;

        using var context = new SqliteIdentityDbContext<TestProfile>(options);

        var profileType = context.Model.FindEntityType(
            typeof(UserProfileEntity<TestProfile>));
        var profileProperty = profileType?.FindProperty(
            nameof(UserProfileEntity<TestProfile>.Profile));
        Assert.NotNull(profileProperty);
        Assert.Equal("TEXT", profileProperty.GetColumnType());

        var userType = context.Model.FindEntityType(typeof(AuthUserEntity));
        Assert.NotNull(userType);
        var createdAt = userType.FindProperty(nameof(AuthUserEntity.CreatedAt));
        Assert.NotNull(createdAt);
        Assert.Equal(typeof(long), createdAt.GetValueConverter()?.ProviderClrType);
        Assert.Equal("INTEGER", createdAt.GetColumnType());

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
        AssertUniqueFilteredIndex(
            loginIdentifierType,
            "ux_identity_login_identifiers_active_normalized_key",
            "is_active = 1");

        var challengeType = context.Model.FindEntityType(
            typeof(VerificationChallengeEntity));
        Assert.NotNull(challengeType);
        AssertUniqueFilteredIndex(
            challengeType,
            "ux_verification_challenges_active_intent",
            "state IN (0, 1)");
    }

    [Fact]
    public void PackagedMigrationIsVisibleForArbitraryProfile()
    {
        var options = new DbContextOptionsBuilder<
                SqliteIdentityDbContext<TestProfile>>()
            .UseSqlite("Data Source=:memory:")
            .Options;

        using var context = new SqliteIdentityDbContext<TestProfile>(options);

        var migration = Assert.Single(
            context.Database.GetMigrations(),
            name => name.EndsWith(
                "_InitialIdentitySchema",
                StringComparison.Ordinal));
        Assert.False(context.Database.HasPendingModelChanges());

        var script = context.GetService<IMigrator>().GenerateScript(
            fromMigration: null,
            toMigration: migration);
        Assert.Contains("CREATE TABLE \"auth_users\"", script, StringComparison.Ordinal);
        Assert.Contains(
            "CREATE UNIQUE INDEX \"ux_identity_login_identifiers_active_normalized_key\"",
            script,
            StringComparison.Ordinal);
        Assert.Contains("WHERE is_active = 1", script, StringComparison.Ordinal);
    }

    private static void AssertUniqueFilteredIndex(
        IReadOnlyEntityType entityType,
        string databaseName,
        string filter)
    {
        var index = Assert.Single(
            entityType.GetIndexes(),
            candidate => candidate.GetDatabaseName() == databaseName);
        Assert.True(index.IsUnique);
        Assert.Equal(filter, index.GetFilter());
    }

    public sealed record TestProfile(string DisplayName);
}
