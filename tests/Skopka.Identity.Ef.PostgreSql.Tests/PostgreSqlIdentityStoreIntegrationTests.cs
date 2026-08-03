using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Skopka.Identity.Authentication;
using Skopka.Identity.Credentials;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Errors;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Registration;
using Skopka.Identity.Sessions;
using Skopka.Identity.SignInMethods;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Skopka.Identity.Users.Queries;
using Skopka.Identity.Verification;
using Testcontainers.PostgreSql;
using Xunit;

namespace Skopka.Identity.Ef.PostgreSql.Tests;

public sealed class PostgreSqlIdentityStoreIntegrationTests
    : IAsyncLifetime
{
    private readonly PostgreSqlContainer postgreSql =
        new PostgreSqlBuilder("postgres:17-alpine")
            .WithDatabase("skopka_identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

    private ServiceProvider serviceProvider = null!;

    public async Task InitializeAsync()
    {
        await postgreSql.StartAsync();

        var services = new ServiceCollection();
        services
            .AddSkopkaIdentity<TestProfile>()
            .UsePostgreSql(
                postgreSql.GetConnectionString(),
                options => options.EnableRetryOnFailure());

        serviceProvider = services.BuildServiceProvider(
            new ServiceProviderOptions
            {
                ValidateOnBuild = true,
                ValidateScopes = true
            });

        await using var scope = serviceProvider.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<
            PostgreSqlIdentityDbContext<TestProfile>>();
        await context.Database.MigrateAsync();
    }

    public async Task DisposeAsync()
    {
        if (serviceProvider is not null)
        {
            await serviceProvider.DisposeAsync();
        }

        await postgreSql.DisposeAsync();
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task MigrationsAndStoreContractsRunAgainstPostgreSql()
    {
        await AssertAllMigrationsAppliedAsync();

        var now = new DateTimeOffset(
            2026,
            7,
            28,
            12,
            0,
            0,
            TimeSpan.Zero);
        await AssertRateLimitRotationAsync(now);
        var created = await CreateUserAsync(
            "alice",
            "alice@example.com",
            "+15551234567",
            "ALICE",
            "ALICE@EXAMPLE.COM",
            "+15551234567",
            new TestProfile("Alice", ["admin", "support"]),
            now);

        await AssertProfileRoundTripAsync(created);
        await AssertAutomaticLookupAsync(created);
        await AssertCrossHandleUpdateCollisionIsAtomicAsync(
            now.AddSeconds(30));
        await AssertDuplicateEmailIsMappedAsync(now.AddMinutes(1));
        await AssertCrossHandleCollisionIsMappedAsync(now.AddMinutes(1));

        await SoftDeleteAsync(created, now.AddMinutes(2));

        var replacement = await CreateUserAsync(
            "alice@example.com",
            "replacement@example.com",
            "+15557654321",
            "ALICE@EXAMPLE.COM",
            "REPLACEMENT@EXAMPLE.COM",
            "+15557654321",
            new TestProfile("Replacement", ["user"]),
            now.AddMinutes(3));

        await AssertRestoreCollisionIsMappedAsync(
            created.Id,
            now.AddMinutes(4));
        await AssertDatabaseConcurrencyTokenAsync(
            replacement.Id,
            now.AddMinutes(5));
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task LoginIdentifierMigrationBackfillsDefaultAliases()
    {
        const string schema = "login_identifier_backfill";
        await using (var connection = new NpgsqlConnection(
            postgreSql.GetConnectionString()))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $"CREATE SCHEMA {schema}";
            await command.ExecuteNonQueryAsync();
        }

        var connectionString = new NpgsqlConnectionStringBuilder(
            postgreSql.GetConnectionString())
        {
            SearchPath = schema
        }.ConnectionString;
        var options = new DbContextOptionsBuilder<
                PostgreSqlIdentityDbContext<TestProfile>>()
            .UseNpgsql(connectionString)
            .Options;

        await using var context =
            new PostgreSqlIdentityDbContext<TestProfile>(options);
        var migrator = context.GetService<IMigrator>();
        await migrator.MigrateAsync(
            "20260730223142_AddRateLimitPartitionVersions");

        var userId = Guid.NewGuid();
        var profile = new UserProfileEntity<TestProfile>
        {
            UserId = userId,
            UserName = "\t+1 (234) 567-8901\t",
            Email = "alice@example.com",
            Phone = "\t+1 555 123 4567\t",
            Profile = new TestProfile("Legacy", [])
        };
        var user = new AuthUserEntity
        {
            Id = userId,
            NormalizedUserName = "+1 (234) 567-8901",
            NormalizedEmail = "ALICE@EXAMPLE.COM",
            NormalizedPhone = "15551234567",
            Version = 1,
            SecurityStamp = "LEGACY-SECURITY-STAMP",
            CreatedAt = DateTimeOffset.UtcNow,
            ModifiedAt = DateTimeOffset.UtcNow,
            Profile = profile
        };
        profile.User = user;
        context.Users.Add(user);
        await context.SaveChangesAsync();

        await migrator.MigrateAsync();
        context.ChangeTracker.Clear();

        var identifiers = await context.LoginIdentifiers
            .AsNoTracking()
            .Where(identifier => identifier.UserId == userId)
            .OrderBy(identifier => identifier.NormalizedKey)
            .ToListAsync();

        Assert.Equal(
            new[]
            {
                "+1 (234) 567-8901",
                "+1 555 123 4567",
                "12345678901",
                "15551234567",
                "ALICE@EXAMPLE.COM"
            },
            identifiers.Select(identifier => identifier.NormalizedKey));
        Assert.All(
            identifiers,
            identifier => Assert.True(identifier.IsActive));
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task LoginIdentifierMigrationRejectsInvalidLegacyPhone()
    {
        const string schema = "login_identifier_invalid_phone";
        await using (var connection = new NpgsqlConnection(
            postgreSql.GetConnectionString()))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $"CREATE SCHEMA {schema}";
            await command.ExecuteNonQueryAsync();
        }

        var connectionString = new NpgsqlConnectionStringBuilder(
            postgreSql.GetConnectionString())
        {
            SearchPath = schema
        }.ConnectionString;
        var options = new DbContextOptionsBuilder<
                PostgreSqlIdentityDbContext<TestProfile>>()
            .UseNpgsql(connectionString)
            .Options;

        await using var context =
            new PostgreSqlIdentityDbContext<TestProfile>(options);
        var migrator = context.GetService<IMigrator>();
        await migrator.MigrateAsync(
            "20260730223142_AddRateLimitPartitionVersions");

        var userId = Guid.NewGuid();
        var profile = new UserProfileEntity<TestProfile>
        {
            UserId = userId,
            UserName = "legacy",
            Email = "legacy@example.com",
            Phone = "call12345678",
            Profile = new TestProfile("Invalid legacy phone", [])
        };
        var user = new AuthUserEntity
        {
            Id = userId,
            NormalizedUserName = "LEGACY",
            NormalizedEmail = "LEGACY@EXAMPLE.COM",
            NormalizedPhone = "12345678",
            Version = 1,
            SecurityStamp = "INVALID-PHONE-STAMP",
            CreatedAt = DateTimeOffset.UtcNow,
            ModifiedAt = DateTimeOffset.UtcNow,
            Profile = profile
        };
        profile.User = user;
        context.Users.Add(user);
        await context.SaveChangesAsync();

        var exception = await Assert.ThrowsAsync<PostgresException>(
            () => migrator.MigrateAsync());
        Assert.Contains(
            "default login-identifier policy",
            exception.MessageText,
            StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task VerificationMigrationBackfillsAndSupersedesLegacyDuplicates()
    {
        const string schema = "verification_supersede_backfill";
        await using (var connection = new NpgsqlConnection(
            postgreSql.GetConnectionString()))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $"CREATE SCHEMA {schema}";
            await command.ExecuteNonQueryAsync();
        }

        var connectionString = new NpgsqlConnectionStringBuilder(
            postgreSql.GetConnectionString())
        {
            SearchPath = schema
        }.ConnectionString;
        var options = new DbContextOptionsBuilder<
                PostgreSqlIdentityDbContext<TestProfile>>()
            .UseNpgsql(connectionString)
            .Options;
        await using var context =
            new PostgreSqlIdentityDbContext<TestProfile>(options);
        var migrator = context.GetService<IMigrator>();
        await migrator.MigrateAsync(
            "20260803152624_AddLoginIdentifierRegistry");

        var now = new DateTimeOffset(
            2026,
            8,
            3,
            11,
            0,
            0,
            TimeSpan.Zero);
        var userStore = new EfIdentityUserStore<TestProfile>(context);
        var created = await userStore.CreateAsync(
            NewUser(Guid.NewGuid(), "legacy-verification"),
            new NormalizedHandles("LEGACY-VERIFICATION", null, null),
            now,
            CancellationToken.None);
        Assert.True(created.IsSuccess);

        var oldestId = Guid.NewGuid();
        var verifiedId = Guid.NewGuid();
        var newestId = Guid.NewGuid();
        var differentId = Guid.NewGuid();

        async Task InsertLegacyChallengeAsync(
            Guid id,
            string binding,
            VerificationChallengeState state,
            DateTimeOffset createdAt)
        {
            await context.Database.ExecuteSqlInterpolatedAsync(
                $"""
                INSERT INTO verification_challenges
                    (id, user_id, purpose, binding, method, verifier,
                     security_stamp, failed_attempt_count, max_attempts,
                     state, version, expires_at, created_at, modified_at)
                VALUES
                    ({id}, {created.Value.Id}, {"password.change"},
                     {binding}, {VerificationMethods.OneTimeCode},
                     {$"legacy-verifier-{id:N}"},
                     {created.Value.SecurityStamp}, {0}, {5}, {(int)state},
                     {1L}, {now.AddMinutes(30)}, {createdAt}, {createdAt})
                """);
        }

        await InsertLegacyChallengeAsync(
            oldestId,
            "same-intent",
            VerificationChallengeState.Pending,
            now);
        await InsertLegacyChallengeAsync(
            verifiedId,
            "same-intent",
            VerificationChallengeState.Verified,
            now.AddSeconds(1));
        await InsertLegacyChallengeAsync(
            newestId,
            "same-intent",
            VerificationChallengeState.Pending,
            now.AddSeconds(2));
        await InsertLegacyChallengeAsync(
            differentId,
            "different-intent",
            VerificationChallengeState.Pending,
            now.AddSeconds(3));

        await migrator.MigrateAsync();
        context.ChangeTracker.Clear();

        var challenges = await context.VerificationChallenges
            .AsNoTracking()
            .Where(challenge => challenge.UserId == created.Value.Id)
            .ToArrayAsync();
        Assert.Equal(4, challenges.Length);
        Assert.Equal(
            VerificationChallengeState.Superseded,
            Assert.Single(challenges, challenge => challenge.Id == oldestId).State);
        Assert.Equal(
            VerificationChallengeState.Superseded,
            Assert.Single(challenges, challenge => challenge.Id == verifiedId).State);
        Assert.Equal(
            VerificationChallengeState.Pending,
            Assert.Single(challenges, challenge => challenge.Id == newestId).State);
        Assert.Equal(
            VerificationChallengeState.Pending,
            Assert.Single(challenges, challenge => challenge.Id == differentId).State);
        Assert.All(challenges, challenge => Assert.Equal(64, challenge.IntentHash.Length));
        var legacyIntentHash = Assert.Single(
            challenges
                .Where(challenge => challenge.Binding == "same-intent")
                .Select(challenge => challenge.IntentHash)
                .Distinct());
        var replacementId = Guid.NewGuid();
        var verificationStore = new EfVerificationChallengeStore<TestProfile>(
            context);
        var replacement = await verificationStore.CreateAndSupersedeAsync(
            new NewVerificationChallenge(
                replacementId,
                created.Value.Id,
                "password.change",
                "same-intent",
                VerificationMethods.OneTimeCode,
                "post-migration-verifier",
                created.Value.SecurityStamp,
                5,
                now.AddHours(1)),
            now.AddMinutes(1),
            CancellationToken.None);
        Assert.True(replacement.IsSuccess);
        context.ChangeTracker.Clear();
        var replacementEntity = await context.VerificationChallenges
            .AsNoTracking()
            .SingleAsync(challenge => challenge.Id == replacementId);
        Assert.Equal(legacyIntentHash, replacementEntity.IntentHash);
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task AtomicExternalRegistrationAndSessionMetadataRunAgainstPostgreSql()
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var registrationStore = services.GetRequiredService<
            IIdentityRegistrationStore<TestProfile>>();
        var userStore = services.GetRequiredService<
            IIdentityUserStore<TestProfile>>();
        var sessionStore = services.GetRequiredService<
            IIdentityRefreshSessionStore<TestProfile>>();
        var userQueries = services.GetRequiredService<
            IIdentityUserQueryService<TestProfile>>();
        var now = new DateTimeOffset(
            2026,
            7,
            30,
            12,
            0,
            0,
            TimeSpan.Zero);
        var login = new ExternalLoginKey("GITHUB", "subject-1");
        var userId = Guid.NewGuid();
        var created = await registrationStore.CreateWithExternalLoginAsync(
            NewUser(userId, "external-user"),
            new NormalizedHandles("EXTERNAL-USER", null, null),
            login,
            now,
            CancellationToken.None);
        Assert.True(created.IsSuccess);

        var secondUserId = Guid.NewGuid();
        var second = await registrationStore.CreateWithExternalLoginAsync(
            NewUser(secondUserId, "external-second"),
            new NormalizedHandles("EXTERNAL-SECOND", null, null),
            new ExternalLoginKey("GITHUB", "subject-2"),
            now.AddSeconds(1),
            CancellationToken.None);
        Assert.True(second.IsSuccess);

        var rejectedUserId = Guid.NewGuid();
        var duplicate = await registrationStore.CreateWithExternalLoginAsync(
            NewUser(rejectedUserId, "duplicate"),
            new NormalizedHandles("DUPLICATE", null, null),
            login,
            now.AddMinutes(1),
            CancellationToken.None);
        Assert.False(duplicate.IsSuccess);
        Assert.Contains(
            duplicate.Errors,
            error => error.Code == IdentityErrorCodes.DuplicateExternalLogin);
        Assert.Null(
            await userStore.FindByIdAsync(
                rejectedUserId,
                CancellationToken.None));

        var queried = await userQueries.QueryAsync(
            new IdentityUserQuery(
                Search: "external",
                Status: IdentityUserStatus.Active,
                PageSize: 1),
            CancellationToken.None);
        Assert.True(queried.IsSuccess);
        Assert.Equal(secondUserId, Assert.Single(queried.Value.Items).Id);
        Assert.NotNull(queried.Value.NextCursor);

        var nextPage = await userQueries.QueryAsync(
            new IdentityUserQuery(
                Search: "external",
                Status: IdentityUserStatus.Active,
                PageSize: 1,
                Cursor: queried.Value.NextCursor),
            CancellationToken.None);
        Assert.True(nextPage.IsSuccess);
        Assert.Equal(userId, Assert.Single(nextPage.Value.Items).Id);
        Assert.Null(nextPage.Value.NextCursor);

        var session = new NewRefreshSession(
            Guid.NewGuid(),
            Guid.NewGuid(),
            userId,
            new string('A', SessionLimits.TokenHashLength),
            created.Value.SecurityStamp,
            now.AddDays(1),
            new IdentitySessionMetadata("web", "integration-test"));
        var sessionCreated = await sessionStore.CreateAsync(
            session,
            now,
            CancellationToken.None);
        Assert.True(sessionCreated.IsSuccess);

        var listed = await sessionStore.ListActiveAsync(
            userId,
            now,
            CancellationToken.None);
        var active = Assert.Single(listed);
        Assert.Equal(session.SessionId, active.SessionId);
        Assert.Equal(session.Metadata, active.Metadata);
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task ConcurrentPasswordRemovalAndExternalUnlinkLeaveOneSignInMethod()
    {
        var now = new DateTimeOffset(
            2026,
            8,
            1,
            12,
            0,
            0,
            TimeSpan.Zero);
        var login = new ExternalLoginKey("CORPORATE", "employee-42");
        IdentityUser<TestProfile> linkedUser;

        await using (var setupScope = serviceProvider.CreateAsyncScope())
        {
            var services = setupScope.ServiceProvider;
            var registrationStore = services.GetRequiredService<
                IIdentityRegistrationStore<TestProfile>>();
            var externalLoginStore = services.GetRequiredService<
                IExternalLoginStore<TestProfile>>();
            var registered = await registrationStore.CreateWithPasswordAsync(
                NewUser(Guid.NewGuid(), "concurrent-methods"),
                new NormalizedHandles("CONCURRENT-METHODS", null, null),
                "opaque-verifier",
                now,
                CancellationToken.None);
            Assert.True(registered.IsSuccess);

            var linked = await externalLoginStore.LinkAsync(
                registered.Value.Id,
                registered.Value.Version,
                login,
                "LINKED-STAMP",
                now.AddMinutes(1),
                CancellationToken.None);
            Assert.True(linked.IsSuccess);
            linkedUser = linked.Value;
        }

        SignInMethodSnapshot snapshot;
        await using (var snapshotScope = serviceProvider.CreateAsyncScope())
        {
            var methods = snapshotScope.ServiceProvider.GetRequiredService<
                IIdentitySignInMethodQueryService<TestProfile>>();
            var result = await methods.GetAsync(
                linkedUser.Id,
                CancellationToken.None);
            Assert.True(result.IsSuccess);
            snapshot = result.Value;
        }

        Assert.True(snapshot.HasPassword);
        Assert.Equal(login, Assert.Single(snapshot.ExternalLogins).Login);

        await using var passwordScope = serviceProvider.CreateAsyncScope();
        await using var externalScope = serviceProvider.CreateAsyncScope();
        var credentialStore = passwordScope.ServiceProvider.GetRequiredService<
            IPasswordCredentialStore<TestProfile>>();
        var externalLoginStoreForUnlink = externalScope.ServiceProvider
            .GetRequiredService<IExternalLoginStore<TestProfile>>();

        var removePasswordTask = credentialStore.ReplacePasswordVerifierAsync(
            snapshot.UserId,
            snapshot.Version,
            expectedPasswordVerifier: "opaque-verifier",
            passwordVerifier: null,
            newSecurityStamp: "PASSWORD-REMOVED-STAMP",
            now.AddMinutes(2),
            CancellationToken.None);
        var unlinkTask = externalLoginStoreForUnlink.UnlinkAsync(
            snapshot.UserId,
            snapshot.Version,
            login,
            "EXTERNAL-UNLINKED-STAMP",
            now.AddMinutes(2),
            CancellationToken.None);

        await Task.WhenAll(removePasswordTask, unlinkTask);
        var passwordResult = await removePasswordTask;
        var unlinkResult = await unlinkTask;

        Assert.NotEqual(passwordResult.IsSuccess, unlinkResult.IsSuccess);
        var failedErrors = passwordResult.IsSuccess
            ? unlinkResult.Errors
            : passwordResult.Errors;
        Assert.Contains(
            failedErrors,
            error => error.Code == IdentityErrorCodes.ConcurrencyConflict);

        await using var finalScope = serviceProvider.CreateAsyncScope();
        var finalMethods = finalScope.ServiceProvider.GetRequiredService<
            IIdentitySignInMethodQueryService<TestProfile>>();
        var finalResult = await finalMethods.GetAsync(
            snapshot.UserId,
            CancellationToken.None);

        Assert.True(finalResult.IsSuccess);
        var availableMethodCount = (finalResult.Value.HasPassword ? 1 : 0)
            + finalResult.Value.ExternalLogins.Count;
        Assert.Equal(1, availableMethodCount);
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task ConcurrentChallengeIssuanceLeavesOneActiveSameIntent()
    {
        var now = new DateTimeOffset(
            2026,
            8,
            3,
            12,
            0,
            0,
            TimeSpan.Zero);
        var user = await CreateUserAsync(
            "otp-concurrency",
            "otp-concurrency@example.com",
            "+15550000001",
            "OTP-CONCURRENCY",
            "OTP-CONCURRENCY@EXAMPLE.COM",
            "+15550000001",
            new TestProfile("OTP concurrency", []),
            now);

        await using var firstScope = serviceProvider.CreateAsyncScope();
        await using var secondScope = serviceProvider.CreateAsyncScope();
        var firstStore = firstScope.ServiceProvider.GetRequiredService<
            IVerificationChallengeStore<TestProfile>>();
        var secondStore = secondScope.ServiceProvider.GetRequiredService<
            IVerificationChallengeStore<TestProfile>>();
        var start = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);

        async Task<Skopka.Abstraction.OperationResult.OperationResult> IssueAsync(
            IVerificationChallengeStore<TestProfile> store,
            Guid challengeId,
            string binding,
            Task startSignal)
        {
            await startSignal;
            return await store.CreateAndSupersedeAsync(
                new NewVerificationChallenge(
                    challengeId,
                    user.Id,
                    "password.change",
                    binding,
                    VerificationMethods.OneTimeCode,
                    $"verifier-{challengeId:N}",
                    user.SecurityStamp,
                    5,
                    now.AddMinutes(5)),
                now,
                CancellationToken.None);
        }

        const string sharedBinding = "channel:email|destination:sha256";
        var firstTask = IssueAsync(
            firstStore,
            Guid.NewGuid(),
            sharedBinding,
            start.Task);
        var secondTask = IssueAsync(
            secondStore,
            Guid.NewGuid(),
            sharedBinding,
            start.Task);
        start.SetResult();
        var results = await Task.WhenAll(firstTask, secondTask);

        Assert.All(results, result => Assert.True(result.IsSuccess));

        await using var assertionScope = serviceProvider.CreateAsyncScope();
        var context = assertionScope.ServiceProvider.GetRequiredService<
            PostgreSqlIdentityDbContext<TestProfile>>();
        var challenges = await context.VerificationChallenges
            .AsNoTracking()
            .Where(challenge => challenge.UserId == user.Id
                && challenge.Purpose == "password.change"
                && challenge.Binding
                    == "channel:email|destination:sha256"
                && challenge.Method == VerificationMethods.OneTimeCode)
            .ToArrayAsync();

        Assert.Equal(2, challenges.Length);
        Assert.Single(
            challenges,
            challenge => challenge.State
                == VerificationChallengeState.Pending);
        var superseded = Assert.Single(
            challenges,
            challenge => challenge.State
                == VerificationChallengeState.Superseded);
        Assert.Equal(2, superseded.Version);
        Assert.Single(
            challenges.Select(challenge => challenge.IntentHash).Distinct());

        await using var thirdScope = serviceProvider.CreateAsyncScope();
        await using var fourthScope = serviceProvider.CreateAsyncScope();
        var thirdStore = thirdScope.ServiceProvider.GetRequiredService<
            IVerificationChallengeStore<TestProfile>>();
        var fourthStore = fourthScope.ServiceProvider.GetRequiredService<
            IVerificationChallengeStore<TestProfile>>();
        var differentStart = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var thirdTask = IssueAsync(
            thirdStore,
            Guid.NewGuid(),
            "channel:sms|destination:first",
            differentStart.Task);
        var fourthTask = IssueAsync(
            fourthStore,
            Guid.NewGuid(),
            "channel:sms|destination:second",
            differentStart.Task);
        differentStart.SetResult();

        var differentResults = await Task.WhenAll(thirdTask, fourthTask);
        Assert.All(differentResults, result => Assert.True(result.IsSuccess));

        context.ChangeTracker.Clear();
        var activeBindings = await context.VerificationChallenges
            .AsNoTracking()
            .Where(challenge => challenge.UserId == user.Id
                && challenge.State == VerificationChallengeState.Pending)
            .Select(challenge => challenge.Binding)
            .OrderBy(binding => binding)
            .ToArrayAsync();
        Assert.Equal(
            new[]
            {
                sharedBinding,
                "channel:sms|destination:first",
                "channel:sms|destination:second"
            }.OrderBy(binding => binding),
            activeBindings);
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task ChallengeCreateReplayRequiresExactPendingRow()
    {
        var now = new DateTimeOffset(
            2026,
            8,
            3,
            13,
            0,
            0,
            TimeSpan.Zero);
        var user = await CreateUserAsync(
            "otp-idempotency",
            "otp-idempotency@example.com",
            "+15550000002",
            "OTP-IDEMPOTENCY",
            "OTP-IDEMPOTENCY@EXAMPLE.COM",
            "+15550000002",
            new TestProfile("OTP idempotency", []),
            now);
        var challenge = new NewVerificationChallenge(
            Guid.NewGuid(),
            user.Id,
            "password.change",
            "channel:email|destination:idempotency",
            VerificationMethods.OneTimeCode,
            "fixed-idempotent-verifier",
            user.SecurityStamp,
            5,
            now.AddMinutes(5).AddTicks(7));

        await using (var firstScope = serviceProvider.CreateAsyncScope())
        {
            var store = firstScope.ServiceProvider.GetRequiredService<
                IVerificationChallengeStore<TestProfile>>();
            Assert.True(
                (await store.CreateAndSupersedeAsync(
                    challenge,
                    now,
                    CancellationToken.None)).IsSuccess);
        }

        await using (var replayScope = serviceProvider.CreateAsyncScope())
        {
            var store = replayScope.ServiceProvider.GetRequiredService<
                IVerificationChallengeStore<TestProfile>>();
            Assert.True(
                (await store.CreateAndSupersedeAsync(
                    challenge,
                    now,
                    CancellationToken.None)).IsSuccess);

            var changedExpiry = await store.CreateAndSupersedeAsync(
                challenge with { ExpiresAt = challenge.ExpiresAt.AddMinutes(1) },
                now,
                CancellationToken.None);
            Assert.False(changedExpiry.IsSuccess);
            Assert.Contains(
                changedExpiry.Errors,
                error => error.Code == IdentityErrorCodes.ConcurrencyConflict);
        }

        var replacement = challenge with
        {
            Id = Guid.NewGuid(),
            Verifier = "replacement-verifier",
            ExpiresAt = now.AddMinutes(6)
        };
        await using (var replacementScope = serviceProvider.CreateAsyncScope())
        {
            var store = replacementScope.ServiceProvider.GetRequiredService<
                IVerificationChallengeStore<TestProfile>>();
            Assert.True(
                (await store.CreateAndSupersedeAsync(
                    replacement,
                    now.AddSeconds(1),
                    CancellationToken.None)).IsSuccess);
        }

        await using var supersededReplayScope =
            serviceProvider.CreateAsyncScope();
        var supersededReplayStore = supersededReplayScope.ServiceProvider
            .GetRequiredService<IVerificationChallengeStore<TestProfile>>();
        var supersededReplay = await supersededReplayStore
            .CreateAndSupersedeAsync(
                challenge,
                now.AddSeconds(2),
                CancellationToken.None);
        Assert.False(supersededReplay.IsSuccess);
        Assert.Contains(
            supersededReplay.Errors,
            error => error.Code == IdentityErrorCodes.ConcurrencyConflict);
    }

    private async Task AssertAllMigrationsAppliedAsync()
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<
            PostgreSqlIdentityDbContext<TestProfile>>();

        var expected = context.Database.GetMigrations().ToArray();
        var applied = (await context.Database.GetAppliedMigrationsAsync())
            .ToArray();

        Assert.NotEmpty(expected);
        Assert.Equal(expected, applied);
        Assert.False(context.Database.HasPendingModelChanges());
    }

    private async Task AssertRateLimitRotationAsync(
        DateTimeOffset now)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var store = services.GetRequiredService<
            IRateLimitBucketStore<TestProfile>>();
        var context = services.GetRequiredService<
            PostgreSqlIdentityDbContext<TestProfile>>();
        var previous = new RateLimitPartition(
            RateLimitLimits.LegacyPartitionVersion,
            new string('A', RateLimitLimits.KeyHashLength));
        var current = new RateLimitPartition(
            "rate-limit-2026-07",
            new string('B', RateLimitLimits.KeyHashLength));

        Assert.True(
            (await store.HitAsync(
                "integration.rotation",
                [previous],
                permitLimit: 2,
                TimeSpan.FromMinutes(1),
                minimumInterval: null,
                now,
                CancellationToken.None)).IsAllowed);
        Assert.True(
            (await store.HitAsync(
                "integration.rotation",
                [current, previous],
                permitLimit: 2,
                TimeSpan.FromMinutes(1),
                minimumInterval: null,
                now.AddSeconds(1),
                CancellationToken.None)).IsAllowed);
        Assert.False(
            (await store.HitAsync(
                "integration.rotation",
                [previous],
                permitLimit: 2,
                TimeSpan.FromMinutes(1),
                minimumInterval: null,
                now.AddSeconds(2),
                CancellationToken.None)).IsAllowed);

        var buckets = await context.RateLimitBuckets
            .Where(bucket =>
                bucket.Scope == "integration.rotation")
            .OrderBy(bucket => bucket.PartitionVersion)
            .ToListAsync();
        Assert.Equal(2, buckets.Count);
        Assert.All(
            buckets,
            bucket => Assert.Equal(2, bucket.HitCount));
        Assert.Equal(
            [
                RateLimitLimits.LegacyPartitionVersion,
                "rate-limit-2026-07",
            ],
            buckets.Select(bucket => bucket.PartitionVersion));
    }

    private static NewIdentityUser<TestProfile> NewUser(
        Guid id,
        string userName)
        => new(
            userName,
            null,
            null,
            new TestProfile(userName, []),
            UserFlags.None,
            $"STAMP-{Guid.NewGuid():N}",
            id);

    private async Task<IdentityUser<TestProfile>> CreateUserAsync(
        string userName,
        string email,
        string phone,
        string normalizedUserName,
        string normalizedEmail,
        string normalizedPhone,
        TestProfile profile,
        DateTimeOffset now)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IIdentityUserStore<TestProfile>>();

        var result = await store.CreateAsync(
            new NewIdentityUser<TestProfile>(
                userName,
                email,
                phone,
                profile,
                UserFlags.None,
                $"STAMP-{Guid.NewGuid():N}"),
            new NormalizedHandles(
                normalizedUserName,
                normalizedEmail,
                normalizedPhone,
                new[]
                {
                    normalizedUserName,
                    normalizedEmail,
                    normalizedPhone
                }.Distinct(StringComparer.Ordinal).ToArray()),
            now,
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        return result.Value;
    }

    private async Task AssertProfileRoundTripAsync(
        IdentityUser<TestProfile> created)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IIdentityUserStore<TestProfile>>();

        var found = await store.FindByIdAsync(
            created.Id,
            CancellationToken.None);

        Assert.NotNull(found);
        Assert.Equal(created.Id, found.Id);
        Assert.Equal(created.Flags, found.Flags);
        Assert.Equal(created.UserName, found.UserName);
        Assert.Equal(created.Email, found.Email);
        Assert.Equal(created.Phone, found.Phone);
        Assert.Equal(created.Profile.DisplayName, found.Profile.DisplayName);
        Assert.Equal(["admin", "support"], found.Profile.Tags);
        Assert.Equal(created.Version, found.Version);
        Assert.Equal(created.SecurityStamp, found.SecurityStamp);
        Assert.Equal(created.CreatedAt, found.CreatedAt);
        Assert.Equal(created.ModifiedAt, found.ModifiedAt);
    }

    private async Task AssertAutomaticLookupAsync(
        IdentityUser<TestProfile> created)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IIdentityUserLookupStore<TestProfile>>();

        var found = await store.FindActiveByNormalizedLoginIdentifiersAsync(
            ["UNKNOWN", "ALICE@EXAMPLE.COM", "ALICE"],
            CancellationToken.None);

        Assert.Single(found);
        Assert.Equal(created.Id, found[0].Id);
    }

    private async Task AssertDuplicateEmailIsMappedAsync(
        DateTimeOffset now)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IIdentityUserStore<TestProfile>>();

        var result = await store.CreateAsync(
            new NewIdentityUser<TestProfile>(
                "bob",
                "alice@example.com",
                null,
                new TestProfile("Bob", []),
                UserFlags.None,
                "STAMP-BOB"),
            new NormalizedHandles(
                "BOB",
                "ALICE@EXAMPLE.COM",
                null),
            now,
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.DuplicateEmail);
    }

    private async Task AssertCrossHandleUpdateCollisionIsAtomicAsync(
        DateTimeOffset now)
    {
        var candidate = await CreateUserAsync(
            "charlie",
            "charlie@example.com",
            "+15559876543",
            "CHARLIE",
            "CHARLIE@EXAMPLE.COM",
            "+15559876543",
            new TestProfile("Charlie", []),
            now);

        await using var scope = serviceProvider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IIdentityUserStore<TestProfile>>();
        var context = scope.ServiceProvider.GetRequiredService<
            PostgreSqlIdentityDbContext<TestProfile>>();

        var result = await store.UpdateHandlesAsync(
            candidate.Id,
            candidate.Version,
            new UpdatedHandles(
                "alice@example.com",
                "ALICE@EXAMPLE.COM",
                candidate.Email,
                "CHARLIE@EXAMPLE.COM",
                candidate.EmailConfirmed,
                candidate.Phone,
                "+15559876543",
                candidate.PhoneConfirmed,
                [
                    "ALICE@EXAMPLE.COM",
                    "CHARLIE@EXAMPLE.COM",
                    "+15559876543"
                ]),
            now.AddSeconds(1),
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Errors,
            error => error.Code
                == IdentityErrorCodes.DuplicateLoginIdentifier);

        var persisted = await store.FindByIdAsync(
            candidate.Id,
            CancellationToken.None);
        Assert.NotNull(persisted);
        Assert.Equal(candidate.UserName, persisted.UserName);
        Assert.Equal(candidate.Version, persisted.Version);

        var keys = await context.LoginIdentifiers
            .AsNoTracking()
            .Where(identifier => identifier.UserId == candidate.Id)
            .Select(identifier => identifier.NormalizedKey)
            .OrderBy(key => key)
            .ToArrayAsync();
        Assert.Equal(
            new[]
            {
                "+15559876543",
                "CHARLIE",
                "CHARLIE@EXAMPLE.COM"
            },
            keys);
    }

    private async Task AssertCrossHandleCollisionIsMappedAsync(
        DateTimeOffset now)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IIdentityUserStore<TestProfile>>();

        var result = await store.CreateAsync(
            new NewIdentityUser<TestProfile>(
                "alice@example.com",
                "bob@example.com",
                null,
                new TestProfile("Bob", []),
                UserFlags.None,
                "STAMP-CROSS-HANDLE"),
            new NormalizedHandles(
                "ALICE@EXAMPLE.COM",
                "BOB@EXAMPLE.COM",
                null,
                ["ALICE@EXAMPLE.COM", "BOB@EXAMPLE.COM"]),
            now,
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Errors,
            error => error.Code
                == IdentityErrorCodes.DuplicateLoginIdentifier);
    }

    private async Task SoftDeleteAsync(
        IdentityUser<TestProfile> user,
        DateTimeOffset now)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IIdentityUserStore<TestProfile>>();

        var result = await store.UpdateStateAsync(
            user.Id,
            user.Version,
            now,
            user.BlockedAt,
            user.BlockedUntil,
            "DELETED-STAMP",
            now,
            CancellationToken.None);

        Assert.True(result.IsSuccess);
    }

    private async Task AssertRestoreCollisionIsMappedAsync(
        Guid userId,
        DateTimeOffset now)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IIdentityUserStore<TestProfile>>();
        var deleted = await store.FindByIdAsync(
            userId,
            CancellationToken.None);

        Assert.NotNull(deleted);
        var result = await store.UpdateStateAsync(
            deleted.Id,
            deleted.Version,
            deletedAt: null,
            deleted.BlockedAt,
            deleted.BlockedUntil,
            newSecurityStamp: null,
            now,
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Errors,
            error => error.Code
                == IdentityErrorCodes.DuplicateLoginIdentifier);
    }

    private async Task AssertDatabaseConcurrencyTokenAsync(
        Guid userId,
        DateTimeOffset now)
    {
        await using var firstScope = serviceProvider.CreateAsyncScope();
        await using var secondScope = serviceProvider.CreateAsyncScope();
        var firstContext = firstScope.ServiceProvider.GetRequiredService<
            PostgreSqlIdentityDbContext<TestProfile>>();
        var secondContext = secondScope.ServiceProvider.GetRequiredService<
            PostgreSqlIdentityDbContext<TestProfile>>();

        var firstUser = await firstContext.Users.SingleAsync(
            user => user.Id == userId);
        var secondUser = await secondContext.Users.SingleAsync(
            user => user.Id == userId);

        firstUser.Version++;
        firstUser.ModifiedAt = now;
        secondUser.Version++;
        secondUser.ModifiedAt = now.AddSeconds(1);

        await firstContext.SaveChangesAsync();
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(
            () => secondContext.SaveChangesAsync());
    }

    public sealed record TestProfile(
        string DisplayName,
        IReadOnlyList<string> Tags);
}
