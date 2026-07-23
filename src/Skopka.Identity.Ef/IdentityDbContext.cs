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

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.ApplyConfiguration(new AuthUserConfiguration());
        modelBuilder.ApplyConfiguration(new UserProfileBaseConfiguration());
        modelBuilder.ApplyConfiguration(new UserProfileConfiguration<TProfile>());
        modelBuilder.ApplyConfiguration(new UserCredentialConfiguration());
        modelBuilder.ApplyConfiguration(new UserExternalLoginConfiguration());

        ConfigureProviderModel(modelBuilder);
    }

    protected virtual void ConfigureProviderModel(ModelBuilder modelBuilder)
    {
    }
}
