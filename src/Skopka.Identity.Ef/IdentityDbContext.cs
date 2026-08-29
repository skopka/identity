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
    public DbSet<LoginIdentifierEntity> LoginIdentifiers
        => Set<LoginIdentifierEntity>();
    public DbSet<VerificationChallengeEntity> VerificationChallenges
        => Set<VerificationChallengeEntity>();
    public DbSet<TotpFactorEntity> TotpFactors => Set<TotpFactorEntity>();
    public DbSet<TotpRecoveryCodeEntity> TotpRecoveryCodes
        => Set<TotpRecoveryCodeEntity>();
    public DbSet<RateLimitBucketEntity> RateLimitBuckets
        => Set<RateLimitBucketEntity>();
    public DbSet<RefreshSessionEntity> RefreshSessions
        => Set<RefreshSessionEntity>();
    public DbSet<IdentitySessionEntity> Sessions
        => Set<IdentitySessionEntity>();
    public DbSet<RoleEntity> Roles => Set<RoleEntity>();
    public DbSet<UserRoleEntity> UserRoles => Set<UserRoleEntity>();
    public DbSet<DeviceAuthorizationRequestEntity>
        DeviceAuthorizationRequests => Set<DeviceAuthorizationRequestEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.ApplyConfiguration(new AuthUserConfiguration());
        modelBuilder.ApplyConfiguration(new UserProfileBaseConfiguration());
        modelBuilder.ApplyConfiguration(new UserProfileConfiguration<TProfile>());
        modelBuilder.ApplyConfiguration(new UserCredentialConfiguration());
        modelBuilder.ApplyConfiguration(new UserExternalLoginConfiguration());
        modelBuilder.ApplyConfiguration(new LoginIdentifierConfiguration());
        modelBuilder.ApplyConfiguration(new VerificationChallengeConfiguration());
        modelBuilder.ApplyConfiguration(new TotpFactorConfiguration());
        modelBuilder.ApplyConfiguration(new TotpRecoveryCodeConfiguration());
        modelBuilder.ApplyConfiguration(new RateLimitBucketConfiguration());
        modelBuilder.ApplyConfiguration(new RefreshSessionConfiguration());
        modelBuilder.ApplyConfiguration(new IdentitySessionConfiguration());
        modelBuilder.ApplyConfiguration(new RoleConfiguration());
        modelBuilder.ApplyConfiguration(new UserRoleConfiguration());
        modelBuilder.ApplyConfiguration(
            new DeviceAuthorizationRequestConfiguration());

        ConfigureProviderModel(modelBuilder);
    }

    protected virtual void ConfigureProviderModel(ModelBuilder modelBuilder)
    {
    }
}
