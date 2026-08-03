using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Migrations;
using Skopka.Identity.Ef.Entities;

namespace Skopka.Identity.Ef.PostgreSql;

public sealed class PostgreSqlIdentityDbContext<TProfile>(
    DbContextOptions<PostgreSqlIdentityDbContext<TProfile>> options)
    : IdentityDbContext<TProfile>(options)
{
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        base.OnConfiguring(optionsBuilder);
        optionsBuilder.ReplaceService<IMigrationsAssembly, PostgreSqlIdentityMigrationsAssembly>();
    }

    protected override void ConfigureProviderModel(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<UserProfileEntity<TProfile>>()
            .Property(profile => profile.Profile)
            .HasColumnType("jsonb");

        var users = modelBuilder.Entity<AuthUserEntity>();

        users.HasIndex(user => user.NormalizedUserName)
            .IsUnique()
            .HasDatabaseName(PostgreSqlIdentityConstraintNames.UserName)
            .HasFilter("deleted_at IS NULL AND normalized_user_name IS NOT NULL");

        users.HasIndex(user => user.NormalizedEmail)
            .IsUnique()
            .HasDatabaseName(PostgreSqlIdentityConstraintNames.Email)
            .HasFilter("deleted_at IS NULL AND normalized_email IS NOT NULL");

        users.HasIndex(user => user.NormalizedPhone)
            .IsUnique()
            .HasDatabaseName(PostgreSqlIdentityConstraintNames.Phone)
            .HasFilter("deleted_at IS NULL AND normalized_phone IS NOT NULL");

        modelBuilder.Entity<LoginIdentifierEntity>()
            .HasIndex(identifier => identifier.NormalizedKey)
            .IsUnique()
            .HasDatabaseName(
                PostgreSqlIdentityConstraintNames.LoginIdentifier)
            .HasFilter("is_active = TRUE");

        modelBuilder.Entity<VerificationChallengeEntity>()
            .HasIndex(challenge => new
            {
                challenge.UserId,
                challenge.IntentHash
            })
            .IsUnique()
            .HasDatabaseName(
                PostgreSqlIdentityConstraintNames.ActiveVerificationIntent)
            .HasFilter("state IN (0, 1)");
    }
}
