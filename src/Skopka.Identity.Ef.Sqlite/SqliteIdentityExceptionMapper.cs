using System.Diagnostics.CodeAnalysis;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;

namespace Skopka.Identity.Ef.Sqlite;

public sealed class SqliteIdentityExceptionMapper : IEfIdentityExceptionMapper
{
    private const int ConstraintError = 19;
    private const int PrimaryKeyConstraintError = 1555;
    private const int UniqueConstraintError = 2067;

    public bool TryMap(
        DbUpdateException exception,
        [NotNullWhen(true)] out Error? error)
    {
        var sqliteException = exception.InnerException as SqliteException
            ?? exception.GetBaseException() as SqliteException;

        if (sqliteException is null
            || sqliteException.SqliteErrorCode != ConstraintError
            || sqliteException.SqliteExtendedErrorCode is not (
                PrimaryKeyConstraintError or UniqueConstraintError))
        {
            error = null;
            return false;
        }

        error = MapUniqueViolation(sqliteException.Message);
        return error is not null;
    }

    private static Error? MapUniqueViolation(string message)
    {
        if (ContainsColumn(message, "auth_users.normalized_user_name"))
        {
            return Duplicate(
                IdentityErrorCodes.DuplicateUserName,
                "User name is already in use.");
        }

        if (ContainsColumn(message, "auth_users.normalized_email"))
        {
            return Duplicate(
                IdentityErrorCodes.DuplicateEmail,
                "Email is already in use.");
        }

        if (ContainsColumn(message, "auth_users.normalized_phone"))
        {
            return Duplicate(
                IdentityErrorCodes.DuplicatePhone,
                "Phone is already in use.");
        }

        if (ContainsColumn(
                message,
                "identity_login_identifiers.normalized_key"))
        {
            return Duplicate(
                IdentityErrorCodes.DuplicateLoginIdentifier,
                "Login identifier is already in use.");
        }

        if (ContainsColumn(message, "identity_roles.normalized_name"))
        {
            return Duplicate(
                IdentityErrorCodes.DuplicateRoleName,
                "Role name is already in use.");
        }

        if (ContainsColumn(message, "identity_user_roles.user_id")
            && ContainsColumn(message, "identity_user_roles.role_id"))
        {
            return Duplicate(
                IdentityErrorCodes.RoleAlreadyAssigned,
                "Role is already assigned to the user.");
        }

        if (ContainsColumn(message, "user_external_logins.provider")
            && ContainsColumn(message, "user_external_logins.subject"))
        {
            return Duplicate(
                IdentityErrorCodes.DuplicateExternalLogin,
                "External login is already linked to another user.");
        }

        return null;
    }

    private static bool ContainsColumn(string message, string column)
        => message.Contains(column, StringComparison.OrdinalIgnoreCase);

    private static Error Duplicate(string code, string message)
        => new(code, message, ErrorType.Conflict);
}
