using Microsoft.EntityFrameworkCore;
using Npgsql;
using Skopka.Identity.Errors;
using Xunit;

namespace Skopka.Identity.Ef.PostgreSql.Tests;

public sealed class PostgreSqlIdentityExceptionMapperTests
{
    [Theory]
    [InlineData("ux_auth_users_normalized_user_name", IdentityErrorCodes.DuplicateUserName)]
    [InlineData("ux_auth_users_normalized_email", IdentityErrorCodes.DuplicateEmail)]
    [InlineData("ux_auth_users_normalized_phone", IdentityErrorCodes.DuplicatePhone)]
    [InlineData("ux_identity_roles_normalized_name", IdentityErrorCodes.DuplicateRoleName)]
    [InlineData("pk_identity_user_roles", IdentityErrorCodes.RoleAlreadyAssigned)]
    public void MapsKnownUniqueConstraints(string constraintName, string expectedCode)
    {
        var mapper = new PostgreSqlIdentityExceptionMapper();
        var exception = CreateUniqueViolation(constraintName);

        var mapped = mapper.TryMap(exception, out var error);

        Assert.True(mapped);
        Assert.NotNull(error);
        Assert.Equal(expectedCode, error.Code);
    }

    [Fact]
    public void DoesNotMapUnknownUniqueConstraint()
    {
        var mapper = new PostgreSqlIdentityExceptionMapper();
        var exception = CreateUniqueViolation("ux_other_aggregate");

        var mapped = mapper.TryMap(exception, out var error);

        Assert.False(mapped);
        Assert.Null(error);
    }

    [Theory]
    [InlineData(
        "fk_identity_user_roles_auth_users_user_id",
        IdentityErrorCodes.UserNotFound)]
    [InlineData(
        "fk_identity_roles_identity_roles_parent_id",
        IdentityErrorCodes.RoleNotFound)]
    [InlineData(
        "fk_identity_user_roles_identity_roles_role_id",
        IdentityErrorCodes.RoleNotFound)]
    public void MapsKnownForeignKeyConstraints(
        string constraintName,
        string expectedCode)
    {
        var mapper = new PostgreSqlIdentityExceptionMapper();
        var exception = CreatePostgresException(
            PostgresErrorCodes.ForeignKeyViolation,
            constraintName);

        var mapped = mapper.TryMap(exception, out var error);

        Assert.True(mapped);
        Assert.NotNull(error);
        Assert.Equal(expectedCode, error.Code);
    }

    private static DbUpdateException CreateUniqueViolation(string constraintName)
        => CreatePostgresException(
            PostgresErrorCodes.UniqueViolation,
            constraintName);

    private static DbUpdateException CreatePostgresException(
        string sqlState,
        string constraintName)
    {
        var postgresException = new PostgresException(
            "database constraint violation",
            "ERROR",
            "ERROR",
            sqlState,
            constraintName: constraintName);

        return new DbUpdateException("Database update failed.", postgresException);
    }
}
