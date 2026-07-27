using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Ef.Entities;
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

    public sealed record TestProfile(string DisplayName);
}
