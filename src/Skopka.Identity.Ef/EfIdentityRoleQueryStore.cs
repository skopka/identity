using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Roles.Queries;

namespace Skopka.Identity.Ef;

public sealed class EfIdentityRoleQueryStore<TProfile>(
    IdentityDbContext<TProfile> dbContext)
    : IIdentityRoleQueryStore<TProfile>
{
    public async Task<IdentityRolePage> QueryAsync(
        IdentityRoleStoreQuery query,
        CancellationToken ct)
    {
        var roles = dbContext.Roles
            .AsNoTracking()
            .AsQueryable();

        if (query.NormalizedName is not null)
        {
            roles = roles.Where(role => role.NormalizedName.Contains(
                query.NormalizedName));
        }

        if (query.Cursor is not null)
        {
            roles = roles.Where(role =>
                role.CreatedAt < query.Cursor.CreatedAt
                || (role.CreatedAt == query.Cursor.CreatedAt
                    && role.Id.CompareTo(query.Cursor.Id) < 0));
        }

        var selected = await roles
            .OrderByDescending(role => role.CreatedAt)
            .ThenByDescending(role => role.Id)
            .Take(query.PageSize + 1)
            .ToListAsync(ct);
        var hasMore = selected.Count > query.PageSize;
        if (hasMore)
        {
            selected.RemoveAt(selected.Count - 1);
        }

        var items = selected
            .Select(EfIdentityRoleStore<TProfile>.ToModel)
            .ToArray();
        var last = selected.LastOrDefault();
        var nextCursor = hasMore && last is not null
            ? new IdentityRoleCursor(last.CreatedAt, last.Id)
            : null;

        return new IdentityRolePage(items, nextCursor);
    }
}
