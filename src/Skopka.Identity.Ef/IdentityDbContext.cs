using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Ef.Configurations;
using Skopka.Identity.Ef.Entities;

namespace Skopka.Identity.Ef;

public class IdentityDbContext<TProfile>(DbContextOptions options) : DbContext(options)
{
    public DbSet<AuthUserEntity> Users => Set<AuthUserEntity>();
    public DbSet<UserProfileEntity<TProfile>> Profiles => Set<UserProfileEntity<TProfile>>();
    public DbSet<UserCredentialEntity> Credentials => Set<UserCredentialEntity>();
    public DbSet<UserExternalLoginEntity> ExternalLogins => Set<UserExternalLoginEntity>();
    public DbSet<VerificationChallengeEntity> VerificationChallenges
        => Set<VerificationChallengeEntity>();
    public DbSet<RateLimitBucketEntity> RateLimitBuckets
        => Set<RateLimitBucketEntity>();
    public DbSet<RefreshSessionEntity> RefreshSessions
        => Set<RefreshSessionEntity>();
    public DbSet<RoleEntity> Roles => Set<RoleEntity>();
    public DbSet<UserRoleEntity> UserRoles => Set<UserRoleEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.ApplyConfiguration(new AuthUserConfiguration());
        modelBuilder.ApplyConfiguration(new UserProfileBaseConfiguration());
        modelBuilder.ApplyConfiguration(new UserProfileConfiguration<TProfile>());
        modelBuilder.ApplyConfiguration(new UserCredentialConfiguration());
        modelBuilder.ApplyConfiguration(new UserExternalLoginConfiguration());
        modelBuilder.ApplyConfiguration(new VerificationChallengeConfiguration());
        modelBuilder.ApplyConfiguration(new RateLimitBucketConfiguration());
        modelBuilder.ApplyConfiguration(new RefreshSessionConfiguration());
        modelBuilder.ApplyConfiguration(new RoleConfiguration());
        modelBuilder.ApplyConfiguration(new UserRoleConfiguration());

        ConfigureProviderModel(modelBuilder);
    }

    protected virtual void ConfigureProviderModel(ModelBuilder modelBuilder)
    {
    }
}
