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

    private static DbUpdateException CreateUniqueViolation(string constraintName)
    {
        var postgresException = new PostgresException(
            "duplicate key value violates unique constraint",
            "ERROR",
            "ERROR",
            PostgresErrorCodes.UniqueViolation,
            constraintName: constraintName);

        return new DbUpdateException("Database update failed.", postgresException);
    }
}
