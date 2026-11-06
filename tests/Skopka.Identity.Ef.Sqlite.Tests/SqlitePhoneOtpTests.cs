using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Skopka.Identity.Errors;
using Skopka.Identity.PhoneOtp;
using Skopka.Identity.Registration;
using Skopka.Identity.SignInMethods;
using Skopka.Identity.Users.Commands;
using Xunit;

namespace Skopka.Identity.Ef.Sqlite.Tests;

public sealed class SqlitePhoneOtpTests
{
    [Fact]
    public async Task UnknownNumberRegistersOnceAndThenSignsIn()
    {
        await using var connection = new SqliteConnection(
            "Data Source=:memory:;Foreign Keys=True");
        await connection.OpenAsync();
        var services = new ServiceCollection();
        services.AddSkopkaIdentity<TestProfile>()
            .UseSqlite(connection)
            .UseHmacOneTimeCodes("test", Enumerable.Repeat((byte)7, 32).ToArray())
            .UseHmacRateLimiting(
                Enumerable.Repeat((byte)9, 32).ToArray(),
                options => options.VerificationResendCooldown =
                    TimeSpan.FromMilliseconds(1));
        await using var provider = services.BuildServiceProvider();
        await using (var scope = provider.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<
                SqliteIdentityDbContext<TestProfile>>();
            await db.Database.MigrateAsync();
        }

        string code;
        Guid challengeId;
        await using (var scope = provider.CreateAsyncScope())
        {
            var otp = scope.ServiceProvider.GetRequiredService<
                IIdentityPhoneOtpService<TestProfile>>();
            var issued = await otp.BeginAsync(
                new BeginPhoneOtpCommand("+7 999 123-45-67", "client"),
                CancellationToken.None);
            Assert.True(issued.IsSuccess);
            Assert.Equal("+79991234567", issued.Value.Phone);
            challengeId = issued.Value.ChallengeId;
            code = issued.Value.DeliveryCode;

            var wrong = await otp.VerifyAsync(
                new VerifyPhoneOtpCommand(
                    challengeId,
                    code == "000000" ? "111111" : "000000",
                    "client"),
                CancellationToken.None);
            Assert.False(wrong.IsSuccess);
            Assert.Contains(wrong.Errors,
                error => error.Code == IdentityErrorCodes.VerificationResponseInvalid);

            var verified = await otp.VerifyAsync(
                new VerifyPhoneOtpCommand(challengeId, code, "client"),
                CancellationToken.None);
            Assert.True(verified.IsSuccess);
            Assert.Null(verified.Value.User);
            Assert.NotNull(verified.Value.RegistrationProof);

            var registration = scope.ServiceProvider.GetRequiredService<
                IIdentityRegistrationService<TestProfile>>();
            var command = new RegisterVerifiedPhoneUserCommand<TestProfile>(
                new CreateUserCommand<TestProfile>(
                    null, null, verified.Value.Phone,
                    new TestProfile("Alice")),
                verified.Value.RegistrationProof!);
            var created = await registration.RegisterVerifiedPhoneAsync(
                command, CancellationToken.None);
            Assert.True(created.IsSuccess);
            Assert.True(created.Value.PhoneConfirmed);
            var methods = await scope.ServiceProvider.GetRequiredService<
                IIdentitySignInMethodQueryService<TestProfile>>()
                .GetAsync(created.Value.Id, CancellationToken.None);
            Assert.True(methods.IsSuccess);
            Assert.True(methods.Value.HasPhoneOtp);
            Assert.False(methods.Value.HasPassword);

            var replay = await registration.RegisterVerifiedPhoneAsync(
                command, CancellationToken.None);
            Assert.False(replay.IsSuccess);
            Assert.Contains(replay.Errors,
                error => error.Code == IdentityErrorCodes.VerificationProofInvalid);
        }

        await Task.Delay(20);
        // The same number can obtain a later code and authenticate the
        // confirmed account without creating another user.
        await using (var scope = provider.CreateAsyncScope())
        {
            var otp = scope.ServiceProvider.GetRequiredService<
                IIdentityPhoneOtpService<TestProfile>>();
            var issued = await otp.BeginAsync(
                new BeginPhoneOtpCommand("+79991234567", "another-client"),
                CancellationToken.None);
            Assert.True(issued.IsSuccess);
            var signedIn = await otp.VerifyAsync(
                new VerifyPhoneOtpCommand(
                    issued.Value.ChallengeId,
                    issued.Value.DeliveryCode,
                    "another-client"),
                CancellationToken.None);
            Assert.True(signedIn.IsSuccess);
            Assert.NotNull(signedIn.Value.User);
            Assert.Null(signedIn.Value.RegistrationProof);
        }
    }

    [Fact]
    public async Task BindingConsumesVerifiedProofAndRejectsReplayAndOccupiedPhone()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:;Foreign Keys=True");
        await connection.OpenAsync();
        var services = new ServiceCollection();
        services.AddSkopkaIdentity<TestProfile>().UseSqlite(connection)
            .UseHmacOneTimeCodes("test", Enumerable.Repeat((byte)7, 32).ToArray())
            .UseHmacRateLimiting(Enumerable.Repeat((byte)9, 32).ToArray(),
                options => options.VerificationResendCooldown = TimeSpan.FromMilliseconds(1));
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<SqliteIdentityDbContext<TestProfile>>()
            .Database.MigrateAsync();
        var users = scope.ServiceProvider.GetRequiredService<IIdentityUserService<TestProfile>>();
        var first = await users.CreateAsync(new CreateUserCommand<TestProfile>(
            "first", null, null, new TestProfile("First")), CancellationToken.None);
        var second = await users.CreateAsync(new CreateUserCommand<TestProfile>(
            "second", null, null, new TestProfile("Second")), CancellationToken.None);
        Assert.True(first.IsSuccess);
        Assert.True(second.IsSuccess);
        var otp = scope.ServiceProvider.GetRequiredService<IIdentityPhoneOtpService<TestProfile>>();
        var issued = await otp.BeginAsync(new BeginPhoneOtpCommand("+79991234567"), CancellationToken.None);
        Assert.True(issued.IsSuccess);
        var wrong = await otp.VerifyForBindingAsync(new VerifyPhoneOtpCommand(
            issued.Value.ChallengeId, issued.Value.DeliveryCode == "000000" ? "111111" : "000000"), CancellationToken.None);
        Assert.False(wrong.IsSuccess);
        var proof = await otp.VerifyForBindingAsync(new VerifyPhoneOtpCommand(
            issued.Value.ChallengeId, issued.Value.DeliveryCode), CancellationToken.None);
        Assert.True(proof.IsSuccess);
        var command = new BindVerifiedPhoneCommand(first.Value.Id, first.Value.Version,
            issued.Value.Phone, proof.Value);
        var stale = await otp.BindVerifiedPhoneAsync(command with { ExpectedVersion = 0 }, CancellationToken.None);
        Assert.False(stale.IsSuccess);
        var bound = await otp.BindVerifiedPhoneAsync(command, CancellationToken.None);
        Assert.True(bound.IsSuccess);
        Assert.True(bound.Value.PhoneConfirmed);
        Assert.Equal(issued.Value.Phone, bound.Value.Phone);
        Assert.Equal(first.Value.Version + 1, bound.Value.Version);
        var replay = await otp.BindVerifiedPhoneAsync(command, CancellationToken.None);
        Assert.False(replay.IsSuccess);
        Assert.Contains(replay.Errors, error => error.Code == IdentityErrorCodes.VerificationProofInvalid);

        await Task.Delay(20);
        var occupied = await otp.BeginAsync(new BeginPhoneOtpCommand("+79991234567"), CancellationToken.None);
        Assert.True(occupied.IsSuccess);
        var occupiedProof = await otp.VerifyForBindingAsync(new VerifyPhoneOtpCommand(
            occupied.Value.ChallengeId, occupied.Value.DeliveryCode), CancellationToken.None);
        Assert.True(occupiedProof.IsSuccess);
        var db = scope.ServiceProvider.GetRequiredService<SqliteIdentityDbContext<TestProfile>>();
        await using var transaction = await db.Database.BeginTransactionAsync();
        var conflict = await otp.BindVerifiedPhoneAsync(new BindVerifiedPhoneCommand(
            second.Value.Id, second.Value.Version, occupied.Value.Phone, occupiedProof.Value), CancellationToken.None);
        Assert.False(conflict.IsSuccess);
        Assert.Contains(conflict.Errors, error => error.Code is IdentityErrorCodes.DuplicatePhone or IdentityErrorCodes.DuplicateLoginIdentifier);
        await db.SaveChangesAsync();
        var retry = await otp.BindVerifiedPhoneAsync(new BindVerifiedPhoneCommand(
            first.Value.Id, bound.Value.Version, occupied.Value.Phone, occupiedProof.Value), CancellationToken.None);
        Assert.True(retry.IsSuccess);
        await transaction.CommitAsync();
    }

    public sealed record TestProfile(string DisplayName);
}
