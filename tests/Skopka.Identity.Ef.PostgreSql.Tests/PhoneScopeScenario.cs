using Microsoft.Extensions.DependencyInjection;
using Skopka.Identity.Authentication;
using Skopka.Identity.Errors;
using Skopka.Identity.PhoneOtp;
using Skopka.Identity.Registration;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Commands;
using Xunit;

namespace Skopka.Identity.Ef.PostgreSql.Tests;

/// <summary>Phone-scope scenario shared verbatim by both provider test projects.</summary>
internal static class PhoneScopeScenario
{
    public sealed record ScopeProfile(string DisplayName);

    private const string Phone = "+79991234567";
    private const string Staff = "staff";

    public static async Task RunAsync(IServiceProvider provider)
    {
        await using var scope = provider.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var users = services.GetRequiredService<IIdentityUserService<ScopeProfile>>();
        var otp = services.GetRequiredService<IIdentityPhoneOtpService<ScopeProfile>>();
        var registration = services.GetRequiredService<IIdentityRegistrationService<ScopeProfile>>();
        var lookup = services.GetRequiredService<IIdentityUserLookupService<ScopeProfile>>();
        var lookupStore = services.GetRequiredService<IIdentityUserLookupStore<ScopeProfile>>();

        async Task<IssuedPhoneOtpChallenge> BeginAsync()
        {
            await Task.Delay(20); // resend cooldown
            var issued = await otp.BeginAsync(new BeginPhoneOtpCommand(Phone), CancellationToken.None);
            Assert.True(issued.IsSuccess);
            return issued.Value;
        }

        async Task<VerifiedPhoneOtp<ScopeProfile>> SignInAsync(string? phoneScope)
        {
            var issued = await BeginAsync();
            var verified = await otp.VerifyAsync(
                new VerifyPhoneOtpCommand(issued.ChallengeId, issued.DeliveryCode) { PhoneScope = phoneScope },
                CancellationToken.None);
            Assert.True(verified.IsSuccess);
            return verified.Value;
        }

        // A personal account registers with the number on the main site (no scope).
        var unknown = await SignInAsync(null);
        Assert.Null(unknown.User);
        var personal = await registration.RegisterVerifiedPhoneAsync(
            new RegisterVerifiedPhoneUserCommand<ScopeProfile>(
                new CreateUserCommand<ScopeProfile>(null, null, unknown.Phone, new ScopeProfile("Student")),
                unknown.RegistrationProof!),
            CancellationToken.None);
        Assert.True(personal.IsSuccess);
        Assert.Equal(IdentityPhoneScopes.Default, personal.Value.PhoneScope);

        // An invited staff account without a phone binds the same number on the staff site.
        var staff = await users.CreateAsync(
            new CreateUserCommand<ScopeProfile>("staff-ivan", null, null, new ScopeProfile("Ivan")),
            CancellationToken.None);
        Assert.True(staff.IsSuccess);
        Assert.Equal(IdentityPhoneScopes.Default, staff.Value.PhoneScope);
        var bindIssued = await BeginAsync();
        var proof = await otp.VerifyForBindingAsync(
            new VerifyPhoneOtpCommand(bindIssued.ChallengeId, bindIssued.DeliveryCode),
            CancellationToken.None);
        Assert.True(proof.IsSuccess);
        var bound = await otp.BindVerifiedPhoneAsync(
            new BindVerifiedPhoneCommand(staff.Value.Id, staff.Value.Version, Phone, proof.Value) { PhoneScope = Staff },
            CancellationToken.None);
        Assert.True(bound.IsSuccess);
        Assert.Equal(Staff, bound.Value.PhoneScope);
        Assert.True(bound.Value.PhoneConfirmed);

        // Each site signs in its own account with a code.
        Assert.Equal(bound.Value.Id, (await SignInAsync(Staff)).User?.Id);
        Assert.Equal(personal.Value.Id, (await SignInAsync(null)).User?.Id);

        // Exact lookups: no scope means the default scope, never a guess between the two.
        Assert.Equal(personal.Value.Id, (await lookup.FindActiveByPhoneAsync(Phone, CancellationToken.None)).Value.Id);
        Assert.Equal(bound.Value.Id, (await lookup.FindActiveByPhoneAsync(Phone, Staff, CancellationToken.None)).Value.Id);
        var elsewhere = await lookup.FindActiveByPhoneAsync(Phone, "partners", CancellationToken.None);
        Assert.Contains(elsewhere.Errors, error => error.Code == IdentityErrorCodes.UserNotFound);

        // Automatic login keys resolve across scopes, so a shared number is ambiguous there.
        var byKey = await lookupStore.FindActiveByNormalizedLoginIdentifiersAsync(["+79991234567"], CancellationToken.None);
        Assert.Equal(2, byKey.Count);

        // The same scope still refuses a second owner, in both scopes.
        await AssertDuplicateAsync(users.CreateAsync(
            new CreateUserCommand<ScopeProfile>("staff-olga", null, Phone, new ScopeProfile("Olga")) { PhoneScope = Staff },
            CancellationToken.None));
        await AssertDuplicateAsync(users.CreateAsync(
            new CreateUserCommand<ScopeProfile>("student-two", null, Phone, new ScopeProfile("Two")),
            CancellationToken.None));

        // Changing another handle keeps the phone in its scope.
        var renamed = await users.ChangeEmailAsync(
            new ChangeEmailCommand(bound.Value.Id, bound.Value.Version, "ivan@example.com"),
            CancellationToken.None);
        Assert.True(renamed.IsSuccess);
        Assert.Equal(Staff, renamed.Value.PhoneScope);

        // Removing the phone returns the account to the default scope; the scope is set again with a new phone.
        var cleared = await users.ChangePhoneAsync(
            new ChangePhoneCommand(renamed.Value.Id, renamed.Value.Version, null),
            CancellationToken.None);
        Assert.True(cleared.IsSuccess);
        Assert.Equal(IdentityPhoneScopes.Default, cleared.Value.PhoneScope);
        await AssertDuplicateAsync(users.ChangePhoneAsync(
            new ChangePhoneCommand(cleared.Value.Id, cleared.Value.Version, Phone),
            CancellationToken.None));
        var restored = await users.ChangePhoneAsync(
            new ChangePhoneCommand(cleared.Value.Id, cleared.Value.Version, Phone) { PhoneScope = Staff },
            CancellationToken.None);
        Assert.True(restored.IsSuccess);
        Assert.Equal(Staff, restored.Value.PhoneScope);
        Assert.False(restored.Value.PhoneConfirmed);

        // Scopes are trusted ordinal identifiers; malformed values are rejected.
        var invalid = await users.CreateAsync(
            new CreateUserCommand<ScopeProfile>("bad-scope", null, Phone, new ScopeProfile("Bad")) { PhoneScope = " staff" },
            CancellationToken.None);
        Assert.Contains(invalid.Errors, error => error.Code == IdentityErrorCodes.Validation);
    }

    private static async Task AssertDuplicateAsync(Task<Skopka.Abstraction.OperationResult.OperationResult<IdentityUser<ScopeProfile>>> task)
    {
        var result = await task;
        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, error => error.Code == IdentityErrorCodes.DuplicatePhone);
    }
}
