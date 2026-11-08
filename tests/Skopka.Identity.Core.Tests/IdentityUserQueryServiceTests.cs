using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Queries;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class IdentityUserQueryServiceTests
{
    [Fact]
    public async Task QueryNormalizesSearchBeforeCallingStore()
    {
        var store = new FakeStore();
        var service = new IdentityUserQueryService<TestProfile>(
            store,
            new DefaultIdentityNormalizer(),
            new NoopIdentityMetrics());

        var result = await service.QueryAsync(
            new IdentityUserQuery("  Alice  "),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("ALICE", store.Query!.NormalizedUserName);
        Assert.Equal("ALICE", store.Query.NormalizedEmail);
        Assert.Null(store.Query.NormalizedPhone);
    }

    [Fact]
    public async Task QueryRejectsUnboundedPageSize()
    {
        var store = new FakeStore();
        var service = new IdentityUserQueryService<TestProfile>(
            store,
            new DefaultIdentityNormalizer(),
            new NoopIdentityMetrics());

        var result = await service.QueryAsync(
            new IdentityUserQuery(
                PageSize: IdentityUserQueryLimits.MaximumPageSize + 1),
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Null(store.Query);
    }

    [Fact]
    public async Task QueryPreservesPartialPhoneSearch()
    {
        var store = new FakeStore();
        var service = new IdentityUserQueryService<TestProfile>(
            store,
            new DefaultIdentityNormalizer(),
            new NoopIdentityMetrics());

        var result = await service.QueryAsync(
            new IdentityUserQuery("555"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("555", store.Query!.NormalizedPhone);
    }

    [Fact]
    public async Task RoleFilterAndCountFailClosedOnStoresWithoutMembershipSupport()
    {
        var store = new FakeStore();
        var service = Create(store);

        var filtered = await service.QueryAsync(
            new IdentityUserQuery { RoleIds = [Guid.NewGuid()] },
            CancellationToken.None);
        var counted = await service.CountAsync(
            new IdentityUserQuery(),
            CancellationToken.None);

        Assert.Contains(filtered.Errors, error => error.Code == IdentityErrorCodes.UserQueryUnsupported);
        Assert.Contains(counted.Errors, error => error.Code == IdentityErrorCodes.UserQueryUnsupported);
        Assert.Null(store.Query);
    }

    [Fact]
    public async Task RoleFilterIsDeduplicatedAndPassedToStore()
    {
        var store = new FakeStore { SupportsRoleMembershipQueries = true, Count = 7 };
        var service = Create(store);
        var role = Guid.NewGuid();

        var counted = await service.CountAsync(
            new IdentityUserQuery("  Alice  ") { RoleIds = [role, role] },
            CancellationToken.None);

        Assert.Equal(7, counted.Value);
        Assert.Equal([role], store.Query!.RoleIds);
        Assert.Equal("ALICE", store.Query.NormalizedUserName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(IdentityUserQueryLimits.MaximumRoleIds + 1)]
    public async Task RoleFilterRejectsEmptyAndOversizedSets(int count)
    {
        var store = new FakeStore { SupportsRoleMembershipQueries = true };
        var service = Create(store);

        var result = await service.QueryAsync(
            new IdentityUserQuery { RoleIds = Enumerable.Range(0, count).Select(_ => Guid.NewGuid()).ToArray() },
            CancellationToken.None);

        Assert.Contains(result.Errors, error => error.Code == IdentityErrorCodes.Validation);
        Assert.Null(store.Query);
    }

    [Fact]
    public async Task RoleFilterRejectsEmptyId()
    {
        var store = new FakeStore { SupportsRoleMembershipQueries = true };

        var result = await Create(store).QueryAsync(
            new IdentityUserQuery { RoleIds = [Guid.Empty] },
            CancellationToken.None);

        Assert.Contains(result.Errors, error => error.Code == IdentityErrorCodes.Validation);
    }

    private static IdentityUserQueryService<TestProfile> Create(FakeStore store)
        => new(store, new DefaultIdentityNormalizer(), new NoopIdentityMetrics());

    private sealed class FakeStore : IIdentityUserQueryStore<TestProfile>
    {
        public IdentityUserStoreQuery? Query { get; private set; }

        public bool SupportsRoleMembershipQueries { get; init; }

        public long Count { get; init; }

        public Task<long> CountAsync(
            IdentityUserStoreQuery query,
            DateTimeOffset now,
            CancellationToken ct)
        {
            Query = query;
            return Task.FromResult(Count);
        }

        public Task<IdentityUserPage<TestProfile>> QueryAsync(
            IdentityUserStoreQuery query,
            DateTimeOffset now,
            CancellationToken ct)
        {
            Query = query;
            return Task.FromResult(
                new IdentityUserPage<TestProfile>([], null));
        }
    }

    public sealed record TestProfile(string DisplayName);
}
