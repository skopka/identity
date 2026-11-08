namespace Skopka.Identity.Users.Queries;

public interface IIdentityUserQueryStore<TProfile>
{
    Task<IdentityUserPage<TProfile>> QueryAsync(
        IdentityUserStoreQuery query,
        DateTimeOffset now,
        CancellationToken ct);

    /// <summary>
    /// True when the store applies <see cref="IdentityUserStoreQuery.RoleIds"/> and
    /// implements <see cref="CountAsync"/>.
    /// </summary>
    /// <remarks>
    /// A custom store written before role filtering would ignore the filter and return
    /// every user. Core therefore refuses role-filtered queries and counts unless the store
    /// opts in here.
    /// </remarks>
    bool SupportsRoleMembershipQueries => false;

    /// <summary>
    /// Counts users matching the search, status, flags and role filter of the query.
    /// Cursor and page size are ignored.
    /// </summary>
    Task<long> CountAsync(
        IdentityUserStoreQuery query,
        DateTimeOffset now,
        CancellationToken ct)
        => throw new NotSupportedException(
            "This user query store does not support counting.");
}
