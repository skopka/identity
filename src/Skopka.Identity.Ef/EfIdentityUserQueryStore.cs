using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Queries;

namespace Skopka.Identity.Ef;

public sealed class EfIdentityUserQueryStore<TProfile>(
    IdentityDbContext<TProfile> dbContext)
    : IIdentityUserQueryStore<TProfile>
{
    public async Task<IdentityUserPage<TProfile>> QueryAsync(
        IdentityUserStoreQuery query,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var profiles = dbContext.Profiles
            .AsNoTracking()
            .Include(profile => profile.User)
            .AsQueryable();

        profiles = ApplySearch(profiles, query);
        profiles = ApplyStatus(profiles, query.Status, now);

        if (query.RequiredFlags != UserFlags.None)
        {
            var flags = (int)query.RequiredFlags;
            profiles = profiles.Where(
                profile => (profile.User.Flags & flags) == flags);
        }

        if (query.Cursor is not null)
        {
            profiles = profiles.Where(
                profile =>
                    profile.User.CreatedAt < query.Cursor.CreatedAt
                    || (profile.User.CreatedAt == query.Cursor.CreatedAt
                        && profile.User.Id.CompareTo(query.Cursor.Id) < 0));
        }

        var selected = await profiles
            .OrderByDescending(profile => profile.User.CreatedAt)
            .ThenByDescending(profile => profile.User.Id)
            .Take(query.PageSize + 1)
            .ToListAsync(ct);
        var hasMore = selected.Count > query.PageSize;
        if (hasMore)
        {
            selected.RemoveAt(selected.Count - 1);
        }

        var items = selected
            .Select(EfIdentityUserStore<TProfile>.ToModel)
            .ToArray();
        var last = selected.LastOrDefault();
        var nextCursor = hasMore && last is not null
            ? new IdentityUserCursor(last.User.CreatedAt, last.User.Id)
            : null;

        return new IdentityUserPage<TProfile>(items, nextCursor);
    }

    private static IQueryable<UserProfileEntity<TProfile>> ApplySearch(
        IQueryable<UserProfileEntity<TProfile>> profiles,
        IdentityUserStoreQuery query)
    {
        if (query.NormalizedUserName is null
            && query.NormalizedEmail is null
            && query.NormalizedPhone is null
            && query.Id is null)
        {
            return profiles;
        }

        return profiles.Where(profile =>
            (query.Id != null && profile.User.Id == query.Id)
            || (query.NormalizedUserName != null
                && profile.User.NormalizedUserName != null
                && profile.User.NormalizedUserName.Contains(
                    query.NormalizedUserName))
            || (query.NormalizedEmail != null
                && profile.User.NormalizedEmail != null
                && profile.User.NormalizedEmail.Contains(
                    query.NormalizedEmail))
            || (query.NormalizedPhone != null
                && profile.User.NormalizedPhone != null
                && profile.User.NormalizedPhone.Contains(
                    query.NormalizedPhone)));
    }

    private static IQueryable<UserProfileEntity<TProfile>> ApplyStatus(
        IQueryable<UserProfileEntity<TProfile>> profiles,
        IdentityUserStatus status,
        DateTimeOffset now)
        => status switch
        {
            IdentityUserStatus.Active => profiles.Where(profile =>
                profile.User.DeletedAt == null
                && (profile.User.BlockedAt == null
                    || (profile.User.BlockedUntil != null
                        && profile.User.BlockedUntil <= now))),
            IdentityUserStatus.Blocked => profiles.Where(profile =>
                profile.User.DeletedAt == null
                && profile.User.BlockedAt != null
                && (profile.User.BlockedUntil == null
                    || profile.User.BlockedUntil > now)),
            IdentityUserStatus.Deleted => profiles.Where(
                profile => profile.User.DeletedAt != null),
            _ => profiles,
        };
}
