using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Metrics;

namespace Skopka.Identity.Roles.Queries;

public sealed class IdentityRoleQueryService<TProfile>(
    IIdentityRoleQueryStore<TProfile> store,
    IIdentityRoleNormalizer normalizer,
    IIdentityMetrics metrics)
    : IIdentityRoleQueryService<TProfile>
{
    public async Task<OperationResult<IdentityRolePage>> QueryAsync(
        IdentityRoleQuery query,
        CancellationToken ct)
    {
        using var op = metrics.Begin("role.query");

        var validationError = Validate(query);
        if (validationError is not null)
        {
            op.Failure(validationError.Code);
            return OperationResultFactory.Fail<IdentityRolePage>(
                validationError);
        }

        var search = string.IsNullOrWhiteSpace(query.Search)
            ? null
            : query.Search.Trim();
        var storeQuery = new IdentityRoleStoreQuery(
            normalizer.NormalizeName(search),
            query.PageSize,
            query.Cursor);
        var page = await store.QueryAsync(storeQuery, ct);

        op.Success();
        return OperationResultFactory.Success(page);
    }

    private static Error? Validate(IdentityRoleQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);

        if (query.PageSize is < 1 or > IdentityRoleQueryLimits.MaximumPageSize)
        {
            return IdentityRoleErrors.Validation(
                "pageSize",
                $"PageSize must be between 1 and {IdentityRoleQueryLimits.MaximumPageSize}.");
        }

        if (query.Search?.Trim().Length
            > IdentityRoleQueryLimits.MaximumSearchLength)
        {
            return IdentityRoleErrors.Validation(
                "search",
                $"Search cannot exceed {IdentityRoleQueryLimits.MaximumSearchLength} characters.");
        }

        if (query.Cursor?.Id == Guid.Empty)
        {
            return IdentityRoleErrors.Validation(
                "cursor.id",
                "Cursor Id is required.");
        }

        return null;
    }
}
