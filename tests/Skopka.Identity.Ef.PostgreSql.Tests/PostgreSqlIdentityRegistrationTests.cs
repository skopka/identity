using Microsoft.Extensions.DependencyInjection;
using Skopka.Identity.Metrics;
using Skopka.Identity.Users;
using Xunit;

namespace Skopka.Identity.Ef.PostgreSql.Tests;

public sealed class PostgreSqlIdentityRegistrationTests
{
    [Fact]
    public void RegistersCompleteIdentityServiceGraph()
    {
        var services = new ServiceCollection();

        services
            .AddSkopkaIdentity<TestProfile>()
            .UsePostgreSql("Host=localhost;Database=skopka_identity_di_tests");

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var scopedProvider = scope.ServiceProvider;

        Assert.IsType<DefaultIdentityNormalizer>(
            scopedProvider.GetRequiredService<IIdentityNormalizer>());
        Assert.IsType<DefaultUserOperationPolicy>(
            scopedProvider.GetRequiredService<IUserOperationPolicy>());
        Assert.IsType<IdentityMetrics>(
            scopedProvider.GetRequiredService<IIdentityMetrics>());
        Assert.IsType<IdentityUserService<TestProfile>>(
            scopedProvider.GetRequiredService<IIdentityUserService<TestProfile>>());
        Assert.IsType<EfIdentityUserStore<TestProfile>>(
            scopedProvider.GetRequiredService<IIdentityUserStore<TestProfile>>());

        var providerContext = scopedProvider.GetRequiredService<PostgreSqlIdentityDbContext<TestProfile>>();
        var storeContext = scopedProvider.GetRequiredService<IdentityDbContext<TestProfile>>();

        Assert.Same(providerContext, storeContext);
        Assert.Contains(
            scopedProvider.GetServices<IEfIdentityExceptionMapper>(),
            mapper => mapper is PostgreSqlIdentityExceptionMapper);
    }

    [Fact]
    public void PreservesConsumerOverridesRegisteredFirst()
    {
        var services = new ServiceCollection();
        var normalizer = new TestNormalizer();
        services.AddSingleton<IIdentityNormalizer>(normalizer);

        services.AddSkopkaIdentity<TestProfile>();

        using var provider = services.BuildServiceProvider();

        Assert.Same(normalizer, provider.GetRequiredService<IIdentityNormalizer>());
    }

    public sealed record TestProfile(string DisplayName);

    private sealed class TestNormalizer : IIdentityNormalizer
    {
        public string? NormalizeUserName(string? value) => value;
        public string? NormalizeEmail(string? value) => value;
        public string? NormalizePhone(string? value) => value;
    }
}
