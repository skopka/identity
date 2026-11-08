using Microsoft.Extensions.DependencyInjection;
using Skopka.Identity.Errors;
using Skopka.Identity.Roles;
using Skopka.Identity.Roles.Commands;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Commands;
using Skopka.Identity.Users.Queries;
using Xunit;

namespace Skopka.Identity.Ef.Sqlite.Tests;

/// <summary>Role-membership query scenario shared verbatim by both provider test projects.</summary>
internal static class RoleMemberQueryScenario
{
    public sealed record MemberProfile(string DisplayName);

    public static async Task RunAsync(IServiceProvider provider)
    {
        await using var scope = provider.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<IIdentityUserService<MemberProfile>>();
        var roles = scope.ServiceProvider.GetRequiredService<IIdentityRoleService<MemberProfile>>();
        var queries = scope.ServiceProvider.GetRequiredService<IIdentityUserQueryService<MemberProfile>>();

        async Task<Guid> RoleAsync(string name)
        {
            var created = await roles.CreateAsync(new CreateRoleCommand(name), CancellationToken.None);
            Assert.True(created.IsSuccess);
            return created.Value.Id;
        }

        async Task<IdentityUser<MemberProfile>> UserAsync(string name, string phone, params Guid[] memberOf)
        {
            var created = await users.CreateAsync(
                new CreateUserCommand<MemberProfile>(name, $"{name}@example.com", phone, new MemberProfile(name)),
                CancellationToken.None);
            Assert.True(created.IsSuccess);
            foreach (var role in memberOf)
            {
                Assert.True((await roles.AssignAsync(new AssignRoleCommand(created.Value.Id, role), CancellationToken.None)).IsSuccess);
            }
            return created.Value;
        }

        var teacher = await RoleAsync("Teacher");
        var manager = await RoleAsync("Manager");
        var unused = await RoleAsync("Unused");

        var ivanTeacher = await UserAsync("ivan-teacher", "+79990000001", teacher);
        var olga = await UserAsync("olga-teacher", "+79990000002", teacher, manager);
        var petr = await UserAsync("petr-manager", "+79990000003", manager);
        var student = await UserAsync("ivan-student", "+79990000004");
        var gone = await UserAsync("gone-teacher", "+79990000005", teacher);
        Assert.True((await users.DeleteAsync(new DeleteUserCommand(gone.Id, gone.Version), CancellationToken.None)).IsSuccess);

        async Task<List<Guid>> AllPagesAsync(IdentityUserQuery query)
        {
            var ids = new List<Guid>();
            IdentityUserCursor? cursor = null;
            do
            {
                var page = await queries.QueryAsync(query with { PageSize = 1, Cursor = cursor }, CancellationToken.None);
                Assert.True(page.IsSuccess);
                Assert.True(page.Value.Items.Count <= 1);
                ids.AddRange(page.Value.Items.Select(user => user.Id));
                cursor = page.Value.NextCursor;
            }
            while (cursor is not null);
            return ids;
        }

        async Task<long> CountAsync(IdentityUserQuery query)
        {
            var counted = await queries.CountAsync(query, CancellationToken.None);
            Assert.True(counted.IsSuccess);
            return counted.Value;
        }

        // One role, every status, paged one by one through the shared cursor.
        var teachers = new IdentityUserQuery { RoleIds = [teacher] };
        Assert.Equal(
            new[] { ivanTeacher.Id, olga.Id, gone.Id }.Order(),
            (await AllPagesAsync(teachers)).Order());
        Assert.Equal(3, await CountAsync(teachers));

        // Status still applies: the deleted member drops out.
        var activeTeachers = teachers with { Status = IdentityUserStatus.Active };
        Assert.Equal(new[] { ivanTeacher.Id, olga.Id }.Order(), (await AllPagesAsync(activeTeachers)).Order());
        Assert.Equal(2, await CountAsync(activeTeachers));

        // Any of several roles; a member of both appears once.
        var staff = new IdentityUserQuery(Status: IdentityUserStatus.Active) { RoleIds = [teacher, manager, teacher] };
        var staffIds = await AllPagesAsync(staff);
        Assert.Equal(new[] { ivanTeacher.Id, olga.Id, petr.Id }.Order(), staffIds.Order());
        Assert.Equal(3, await CountAsync(staff));

        // Search by name, email and phone narrows the members, not the whole user list.
        Assert.Equal([ivanTeacher.Id], await AllPagesAsync(staff with { Search = "ivan" }));
        Assert.Equal([olga.Id], await AllPagesAsync(staff with { Search = "olga-teacher@example" }));
        Assert.Equal([petr.Id], await AllPagesAsync(staff with { Search = "0000003" }));
        Assert.Equal(1, await CountAsync(staff with { Search = "ivan" }));

        // Without a role filter the student is listed; with an unused role nobody is.
        Assert.Contains(student.Id, await AllPagesAsync(new IdentityUserQuery(Search: "ivan")));
        Assert.Empty(await AllPagesAsync(new IdentityUserQuery { RoleIds = [unused] }));
        Assert.Equal(0, await CountAsync(new IdentityUserQuery { RoleIds = [unused] }));
        Assert.Equal(4, await CountAsync(new IdentityUserQuery(Status: IdentityUserStatus.Active)));

        var empty = await queries.QueryAsync(new IdentityUserQuery { RoleIds = [] }, CancellationToken.None);
        Assert.False(empty.IsSuccess);
        Assert.Contains(empty.Errors, error => error.Code == IdentityErrorCodes.Validation);
    }
}
