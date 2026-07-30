using Skopka.Abstraction.OperationResult;
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

        var validationError = Validate(query);
        if (validationError is not null)
        {
            op.Failure(validationError.Code);
            return OperationResultFactory.Fail<IdentityUserPage<TProfile>>(
                validationError);
        }

        var search = string.IsNullOrWhiteSpace(query.Search)
            ? null
            : query.Search.Trim();
        var storeQuery = new IdentityUserStoreQuery(
            normalizer.NormalizeUserName(search),
            normalizer.NormalizeEmail(search),
            NormalizePhone(search),
            Guid.TryParse(search, out var id) ? id : null,
            query.Status,
            query.RequiredFlags,
            query.PageSize,
            query.Cursor);
        var page = await store.QueryAsync(
            storeQuery,
            DateTimeOffset.UtcNow,
            ct);

        op.Success();
        return OperationResultFactory.Success(page);
    }

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

        if (query.Cursor?.Id == Guid.Empty)
        {
            return IdentityErrors.Validation(
                "cursor.id",
                "Cursor Id is required.");
        }

        return null;
    }
}
