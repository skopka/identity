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

    private sealed class FakeStore : IIdentityUserQueryStore<TestProfile>
    {
        public IdentityUserStoreQuery? Query { get; private set; }

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
