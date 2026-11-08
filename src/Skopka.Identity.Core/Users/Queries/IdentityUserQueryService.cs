using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;

namespace Skopka.Identity.Users.Queries;

public sealed class IdentityUserQueryService<TProfile>(
    IIdentityUserQueryStore<TProfile> store,
    IIdentityNormalizer normalizer,
    IIdentityMetrics metrics)
    : IIdentityUserQueryService<TProfile>
{
    private const UserFlags KnownFlags =
        UserFlags.System | UserFlags.Protected | UserFlags.ServiceAccount;

    public async Task<OperationResult<IdentityUserPage<TProfile>>> QueryAsync(
        IdentityUserQuery query,
        CancellationToken ct)
    {
        using var op = metrics.Begin("user.query");

        var storeQuery = CreateStoreQuery(query, out var error);
        if (storeQuery is null)
        {
            op.Failure(error!.Code);
            return OperationResultFactory.Fail<IdentityUserPage<TProfile>>(error);
        }

        var page = await store.QueryAsync(
            storeQuery,
            DateTimeOffset.UtcNow,
            ct);

        op.Success();
        return OperationResultFactory.Success(page);
    }

    public async Task<OperationResult<long>> CountAsync(
        IdentityUserQuery query,
        CancellationToken ct)
    {
        using var op = metrics.Begin("user.count");

        var storeQuery = CreateStoreQuery(query, out var error);
        if (storeQuery is null)
        {
            op.Failure(error!.Code);
            return OperationResultFactory.Fail<long>(error);
        }

        if (!store.SupportsRoleMembershipQueries)
        {
            var unsupported = Unsupported();
            op.Failure(unsupported.Code);
            return OperationResultFactory.Fail<long>(unsupported);
        }

        var count = await store.CountAsync(
            storeQuery,
            DateTimeOffset.UtcNow,
            ct);

        op.Success();
        return OperationResultFactory.Success(count);
    }

    private IdentityUserStoreQuery? CreateStoreQuery(
        IdentityUserQuery query,
        out Error? error)
    {
        error = Validate(query);
        if (error is not null)
        {
            return null;
        }

        var roleIds = query.RoleIds?.Distinct().ToArray();
        if (roleIds is not null && !store.SupportsRoleMembershipQueries)
        {
            // A store that predates role filtering would silently return every user.
            error = Unsupported();
            return null;
        }

        var search = string.IsNullOrWhiteSpace(query.Search)
            ? null
            : query.Search.Trim();
        return new IdentityUserStoreQuery(
            normalizer.NormalizeUserName(search),
            normalizer.NormalizeEmail(search),
            NormalizePhone(search),
            Guid.TryParse(search, out var id) ? id : null,
            query.Status,
            query.RequiredFlags,
            query.PageSize,
            query.Cursor)
        {
            RoleIds = roleIds,
        };
    }

    private static Error Unsupported()
        => new(
            IdentityErrorCodes.UserQueryUnsupported,
            "This user query is not supported by the configured store.",
            ErrorType.Forbidden);

    private string? NormalizePhone(string? search)
    {
        var normalized = normalizer.NormalizePhone(search);
        return string.IsNullOrEmpty(normalized) ? null : normalized;
    }

    private static Error? Validate(IdentityUserQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);

        if (!Enum.IsDefined(query.Status))
        {
            return IdentityErrors.Validation("status", "Status is invalid.");
        }

        if ((query.RequiredFlags & ~KnownFlags) != 0)
        {
            return IdentityErrors.Validation(
                "requiredFlags",
                "RequiredFlags contains unsupported values.");
        }

        if (query.PageSize is < 1 or > IdentityUserQueryLimits.MaximumPageSize)
        {
            return IdentityErrors.Validation(
                "pageSize",
                $"PageSize must be between 1 and {IdentityUserQueryLimits.MaximumPageSize}.");
        }

        if (query.Search?.Trim().Length
            > IdentityUserQueryLimits.MaximumSearchLength)
        {
            return IdentityErrors.Validation(
                "search",
                $"Search cannot exceed {IdentityUserQueryLimits.MaximumSearchLength} characters.");
        }

        if (query.RoleIds is not null)
        {
            if (query.RoleIds.Count == 0)
            {
                return IdentityErrors.Validation(
                    "roleIds",
                    "RoleIds cannot be empty; pass null for no role filter.");
            }

            if (query.RoleIds.Contains(Guid.Empty))
            {
                return IdentityErrors.Validation(
                    "roleIds",
                    "RoleIds cannot contain an empty id.");
            }

            if (query.RoleIds.Distinct().Count()
                > IdentityUserQueryLimits.MaximumRoleIds)
            {
                return IdentityErrors.Validation(
                    "roleIds",
                    $"RoleIds cannot exceed {IdentityUserQueryLimits.MaximumRoleIds} distinct values.");
            }
        }

        if (query.Cursor?.Id == Guid.Empty)
        {
            return IdentityErrors.Validation(
                "cursor.id",
                "Cursor Id is required.");
        }

        return null;
    }
}
