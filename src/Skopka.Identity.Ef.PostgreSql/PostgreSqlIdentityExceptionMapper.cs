using System.Diagnostics.CodeAnalysis;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;

namespace Skopka.Identity.Ef.PostgreSql;

public sealed class PostgreSqlIdentityExceptionMapper : IEfIdentityExceptionMapper
{
    public bool TryMap(
        DbUpdateException exception,
        [NotNullWhen(true)] out Error? error)
    {
        var postgresException = exception.InnerException as PostgresException
            ?? exception.GetBaseException() as PostgresException;

        if (postgresException?.SqlState != PostgresErrorCodes.UniqueViolation)
        {
            error = null;
            return false;
        }

        error = postgresException.ConstraintName switch
        {
            PostgreSqlIdentityConstraintNames.UserName => Duplicate(
                IdentityErrorCodes.DuplicateUserName,
                "User name is already in use."),
            PostgreSqlIdentityConstraintNames.Email => Duplicate(
                IdentityErrorCodes.DuplicateEmail,
                "Email is already in use."),
            PostgreSqlIdentityConstraintNames.Phone => Duplicate(
                IdentityErrorCodes.DuplicatePhone,
                "Phone is already in use."),
            _ => null
        };

        return error is not null;
    }

    private static Error Duplicate(string code, string message)
        => new(code, message, ErrorType.Conflict);
}
