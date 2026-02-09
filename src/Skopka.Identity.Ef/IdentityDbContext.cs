using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Ef.Entities;

namespace Skopka.Identity.Ef;

public sealed class IdentityDbContext<TProfile>(DbContextOptions<IdentityDbContext<TProfile>> options) : DbContext(options)
{
    public DbSet<AuthUserEntity> Users => Set<AuthUserEntity>();
    public DbSet<UserProfileEntity<TProfile>> Profiles => Set<UserProfileEntity<TProfile>>();
}
