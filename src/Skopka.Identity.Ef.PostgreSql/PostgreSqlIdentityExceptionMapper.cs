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

        if (postgresException is null)
        {
            error = null;
            return false;
        }

        error = postgresException.SqlState switch
        {
            PostgresErrorCodes.UniqueViolation
                => MapUniqueViolation(postgresException.ConstraintName),
            PostgresErrorCodes.ForeignKeyViolation
                => MapForeignKeyViolation(postgresException.ConstraintName),
            _ => null
        };

        return error is not null;
    }

    private static Error? MapUniqueViolation(string? constraintName)
        => constraintName switch
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
            PostgreSqlIdentityConstraintNames.RoleName => Duplicate(
                IdentityErrorCodes.DuplicateRoleName,
                "Role name is already in use."),
            PostgreSqlIdentityConstraintNames.UserRole => Duplicate(
                IdentityErrorCodes.RoleAlreadyAssigned,
                "Role is already assigned to the user."),
            _ => null
        };

    private static Error? MapForeignKeyViolation(string? constraintName)
        => constraintName switch
        {
            PostgreSqlIdentityConstraintNames.UserRoleUser => new Error(
                IdentityErrorCodes.UserNotFound,
                "User not found.",
                ErrorType.NotFound),
            PostgreSqlIdentityConstraintNames.RoleParent
                or PostgreSqlIdentityConstraintNames.UserRoleRole
                => new Error(
                    IdentityErrorCodes.RoleNotFound,
                    "Role not found.",
                    ErrorType.NotFound),
            _ => null
        };

    private static Error Duplicate(string code, string message)
        => new(code, message, ErrorType.Conflict);
}
