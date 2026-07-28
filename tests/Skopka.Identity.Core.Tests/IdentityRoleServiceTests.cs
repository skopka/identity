using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.Roles;
using Skopka.Identity.Roles.Commands;
using Skopka.Identity.Sessions;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class IdentityRoleServiceTests
{
    [Fact]
    public async Task CreateNormalizesNameAndTrimsDisplayValues()
    {
        var fixture = new Fixture();

        var result = await fixture.Service.CreateAsync(
            new CreateRoleCommand("  Operators  ", "  Operations team  "),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("Operators", result.Value.Name);
        Assert.Equal("Operations team", result.Value.Description);
        Assert.NotNull(fixture.RoleStore.LastCreated);
        Assert.Equal("OPERATORS", fixture.RoleStore.LastCreated.NormalizedName);
    }

    [Fact]
    public async Task CreateRejectsDuplicateNormalizedName()
    {
        var fixture = new Fixture();
        fixture.RoleStore.Add(Role("Operators"));

        var result = await fixture.Service.CreateAsync(
            new CreateRoleCommand("operators"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.DuplicateRoleName);
        Assert.Null(fixture.RoleStore.LastCreated);
    }

    [Fact]
    public async Task CreateRejectsEmptyCustomNormalizationResult()
    {
        var fixture = new Fixture(
            normalizer: new EmptyRoleNormalizer());

        var result = await fixture.Service.CreateAsync(
            new CreateRoleCommand("Operator"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.Validation);
        Assert.Null(fixture.RoleStore.LastCreated);
    }

    [Fact]
    public async Task UpdateRejectsHierarchyCycle()
    {
        var fixture = new Fixture();
        var parent = Role("Parent");
        var child = Role("Child") with { ParentId = parent.Id };
        fixture.RoleStore.Add(parent);
        fixture.RoleStore.Add(child);

        var result = await fixture.Service.UpdateAsync(
            new UpdateRoleCommand(
                parent.Id,
                parent.Version,
                parent.Name,
                ParentId: child.Id),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.Validation);
        Assert.Equal(0, fixture.RoleStore.UpdateCalls);
    }

    [Fact]
    public async Task AssignRejectsProtectedUser()
    {
        var fixture = new Fixture(
            CreateUser() with { Flags = UserFlags.Protected });
        var role = Role("Operators");
        fixture.RoleStore.Add(role);

        var result = await fixture.Service.AssignAsync(
            new AssignRoleCommand(fixture.UserStore.User.Id, role.Id),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.Forbidden);
        Assert.Empty(fixture.UserRoleStore.Memberships);
    }

    [Fact]
    public async Task AssignedRolesAreProjectedAsRepeatedRoleClaims()
    {
        var fixture = new Fixture();
        var first = Role("Auditor");
        var second = Role("Operator");
        fixture.RoleStore.Add(first);
        fixture.RoleStore.Add(second);

        Assert.True((await fixture.Service.AssignAsync(
            new AssignRoleCommand(fixture.UserStore.User.Id, first.Id),
            CancellationToken.None)).IsSuccess);
        Assert.True((await fixture.Service.AssignAsync(
            new AssignRoleCommand(fixture.UserStore.User.Id, second.Id),
            CancellationToken.None)).IsSuccess);

        var claims = await new IdentityRoleSessionClaimsProvider<TestProfile>(
                fixture.UserRoleStore)
            .GetClaimsAsync(fixture.UserStore.User, CancellationToken.None);

        Assert.Equal(
            ["Auditor", "Operator"],
            claims
                .Where(claim => claim.Type == IdentitySessionClaimTypes.Role)
                .Select(claim => claim.Value)
                .Order()
                .ToArray());
    }

    [Fact]
    public async Task RemoveIsIdempotent()
    {
        var fixture = new Fixture();
        var role = Role("Operator");
        fixture.RoleStore.Add(role);

        var result = await fixture.Service.RemoveAsync(
            new RemoveRoleCommand(fixture.UserStore.User.Id, role.Id),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
    }

    private static void AssertError(OperationResult result, string code)
    {
        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, error => error.Code == code);
    }

    private static IdentityRole Role(string name)
    {
        var now = DateTimeOffset.UtcNow;
        return new IdentityRole(
            Guid.NewGuid(),
            name,
            null,
            null,
            1,
            now,
            now);
    }

    private static IdentityUser<TestProfile> CreateUser()
    {
        var now = DateTimeOffset.UtcNow;
        return new IdentityUser<TestProfile>(
            Guid.NewGuid(),
            UserFlags.None,
            "alice",
            "alice@example.com",
            true,
            null,
            false,
            new TestProfile("Alice"),
            1,
            "STAMP",
            null,
            null,
            null,
            now,
            now);
    }

    private sealed class Fixture
    {
        public Fixture(
            IdentityUser<TestProfile>? user = null,
            IIdentityRoleNormalizer? normalizer = null)
        {
            UserStore = new FakeUserStore(user ?? CreateUser());
            RoleStore = new FakeRoleStore();
            UserRoleStore = new FakeUserRoleStore(RoleStore);
            Service = new IdentityRoleService<TestProfile>(
                RoleStore,
                UserRoleStore,
                UserStore,
                normalizer ?? new DefaultIdentityRoleNormalizer(),
                new DefaultUserOperationPolicy(),
                new NoopIdentityMetrics());
        }

        public FakeUserStore UserStore { get; }
        public FakeRoleStore RoleStore { get; }
        public FakeUserRoleStore UserRoleStore { get; }
        public IdentityRoleService<TestProfile> Service { get; }
    }

    private sealed class EmptyRoleNormalizer : IIdentityRoleNormalizer
    {
        public string? NormalizeName(string? value) => null;
    }

    private sealed class FakeRoleStore : IIdentityRoleStore<TestProfile>
    {
        private readonly Dictionary<Guid, IdentityRole> roles = [];

        public NewIdentityRole? LastCreated { get; private set; }
        public int UpdateCalls { get; private set; }

        public void Add(IdentityRole role) => roles.Add(role.Id, role);

        public Task<IdentityRole?> FindByIdAsync(
            Guid roleId,
            CancellationToken ct)
            => Task.FromResult(roles.GetValueOrDefault(roleId));

        public Task<IdentityRole?> FindByNormalizedNameAsync(
            string normalizedName,
            CancellationToken ct)
            => Task.FromResult(
                roles.Values.SingleOrDefault(
                    role => string.Equals(
                        role.Name,
                        normalizedName,
                        StringComparison.OrdinalIgnoreCase)));

        public Task<OperationResult<IdentityRole>> CreateAsync(
            NewIdentityRole role,
            DateTimeOffset now,
            CancellationToken ct)
        {
            LastCreated = role;
            var created = new IdentityRole(
                Guid.NewGuid(),
                role.Name,
                role.Description,
                role.ParentId,
                1,
                now,
                now);
            roles.Add(created.Id, created);
            return Task.FromResult(OperationResultFactory.Success(created));
        }

        public Task<OperationResult<IdentityRole>> UpdateAsync(
            Guid roleId,
            long expectedVersion,
            UpdatedIdentityRole role,
            DateTimeOffset now,
            CancellationToken ct)
        {
            UpdateCalls++;
            var current = roles[roleId];
            var updated = current with
            {
                Name = role.Name,
                Description = role.Description,
                ParentId = role.ParentId,
                Version = current.Version + 1,
                ModifiedAt = now
            };
            roles[roleId] = updated;
            return Task.FromResult(OperationResultFactory.Success(updated));
        }

        public Task<OperationResult> DeleteAsync(
            Guid roleId,
            long expectedVersion,
            CancellationToken ct)
        {
            roles.Remove(roleId);
            return Task.FromResult(OperationResultFactory.Success());
        }
    }

    private sealed class FakeUserRoleStore(FakeRoleStore roleStore)
        : IIdentityUserRoleStore<TestProfile>
    {
        public HashSet<(Guid UserId, Guid RoleId)> Memberships { get; } = [];

        public async Task<IReadOnlyList<IdentityRole>> GetRolesAsync(
            Guid userId,
            CancellationToken ct)
        {
            var roles = new List<IdentityRole>();
            foreach (var membership in Memberships.Where(item => item.UserId == userId))
            {
                var role = await roleStore.FindByIdAsync(membership.RoleId, ct);
                if (role is not null)
                {
                    roles.Add(role);
                }
            }

            return roles;
        }

        public Task<bool> IsInRoleAsync(
            Guid userId,
            Guid roleId,
            CancellationToken ct)
            => Task.FromResult(Memberships.Contains((userId, roleId)));

        public Task<OperationResult> AddAsync(
            Guid userId,
            Guid roleId,
            DateTimeOffset now,
            CancellationToken ct)
        {
            Memberships.Add((userId, roleId));
            return Task.FromResult(OperationResultFactory.Success());
        }

        public Task<OperationResult> RemoveAsync(
            Guid userId,
            Guid roleId,
            CancellationToken ct)
        {
            Memberships.Remove((userId, roleId));
            return Task.FromResult(OperationResultFactory.Success());
        }
    }

    private sealed class FakeUserStore(IdentityUser<TestProfile> user)
        : IIdentityUserStore<TestProfile>
    {
        public IdentityUser<TestProfile> User { get; } = user;

        public Task<IdentityUser<TestProfile>?> FindByIdAsync(
            Guid id,
            CancellationToken ct)
            => Task.FromResult(id == User.Id ? User : null);

        public Task<OperationResult<IdentityUser<TestProfile>>> CreateAsync(
            NewIdentityUser<TestProfile> user,
            NormalizedHandles handles,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult<IdentityUser<TestProfile>>> UpdateHandlesAsync(
            Guid userId,
            long expectedVersion,
            UpdatedHandles updated,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult<IdentityUser<TestProfile>>> UpdateProfileAsync(
            Guid userId,
            long expectedVersion,
            TestProfile profile,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult<IdentityUser<TestProfile>>>
            UpdateSecurityStampAsync(
                Guid userId,
                long expectedVersion,
                string securityStamp,
                DateTimeOffset now,
                CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult> UpdateStateAsync(
            Guid userId,
            long expectedVersion,
            DateTimeOffset? deletedAt,
            DateTimeOffset? blockedAt,
            DateTimeOffset? blockedUntil,
            string? newSecurityStamp,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();
    }

    public sealed record TestProfile(string DisplayName);
}
