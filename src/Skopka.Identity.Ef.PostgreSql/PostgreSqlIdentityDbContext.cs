using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Ef.Entities;

namespace Skopka.Identity.Ef.PostgreSql;

public sealed class PostgreSqlIdentityDbContext<TProfile>(
    DbContextOptions<PostgreSqlIdentityDbContext<TProfile>> options)
    : IdentityDbContext<TProfile>(options)
{
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
    }
}
