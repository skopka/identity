using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Skopka.Identity.Ef.Entities;

namespace Skopka.Identity.Ef.Sqlite;

public sealed class SqliteIdentityDbContext<TProfile>(
    DbContextOptions<SqliteIdentityDbContext<TProfile>> options)
    : IdentityDbContext<TProfile>(options)
{
    private static readonly ValueConverter<DateTimeOffset, long>
        DateTimeOffsetConverter = new(
            value => value.UtcTicks,
            value => new DateTimeOffset(value, TimeSpan.Zero));

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        base.OnConfiguring(optionsBuilder);
        optionsBuilder.ReplaceService<IMigrationsAssembly, SqliteIdentityMigrationsAssembly>();
    }

    protected override void ConfigureProviderModel(ModelBuilder modelBuilder)
    {
        ConfigureDateTimeOffsets(modelBuilder);

        modelBuilder.Entity<UserProfileEntity<TProfile>>()
            .Property(profile => profile.Profile)
            .HasColumnType("TEXT");

        var users = modelBuilder.Entity<AuthUserEntity>();

        users.HasIndex(user => user.NormalizedUserName)
            .IsUnique()
            .HasDatabaseName(SqliteIdentityConstraintNames.UserName)
            .HasFilter("deleted_at IS NULL AND normalized_user_name IS NOT NULL");

        users.HasIndex(user => user.NormalizedEmail)
            .IsUnique()
            .HasDatabaseName(SqliteIdentityConstraintNames.Email)
            .HasFilter("deleted_at IS NULL AND normalized_email IS NOT NULL");

        users.HasIndex(user => user.NormalizedPhone)
            .IsUnique()
            .HasDatabaseName(SqliteIdentityConstraintNames.Phone)
            .HasFilter("deleted_at IS NULL AND normalized_phone IS NOT NULL");

        modelBuilder.Entity<LoginIdentifierEntity>()
            .HasIndex(identifier => identifier.NormalizedKey)
            .IsUnique()
            .HasDatabaseName(SqliteIdentityConstraintNames.LoginIdentifier)
            .HasFilter("is_active = 1");

        modelBuilder.Entity<VerificationChallengeEntity>()
            .HasIndex(challenge => new
            {
                challenge.UserId,
                challenge.IntentHash
            })
            .IsUnique()
            .HasDatabaseName(SqliteIdentityConstraintNames.ActiveVerificationIntent)
            .HasFilter("state IN (0, 1)");
    }

    private static void ConfigureDateTimeOffsets(ModelBuilder modelBuilder)
    {
        foreach (var property in modelBuilder.Model
                     .GetEntityTypes()
                     .SelectMany(entity => entity.GetProperties())
                     .Where(property =>
                         property.ClrType == typeof(DateTimeOffset)
                         || property.ClrType == typeof(DateTimeOffset?)))
        {
            property.SetValueConverter(DateTimeOffsetConverter);
            property.SetColumnType("INTEGER");
        }
    }
}
