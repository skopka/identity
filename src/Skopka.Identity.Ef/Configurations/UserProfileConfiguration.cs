using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Skopka.Identity.Ef.Entities;

namespace Skopka.Identity.Ef.Configurations;

internal sealed class UserProfileBaseConfiguration : IEntityTypeConfiguration<UserProfileEntityBase>
{
    public void Configure(EntityTypeBuilder<UserProfileEntityBase> builder)
    {
        builder.UseTpcMappingStrategy();

        builder.HasKey(profile => profile.UserId);

        builder.Property(profile => profile.UserId).HasColumnName("user_id");
        builder.Property(profile => profile.UserName).HasColumnName("user_name");
        builder.Property(profile => profile.Email).HasColumnName("email");
        builder.Property(profile => profile.Phone).HasColumnName("phone");

        builder.HasOne(profile => profile.User)
            .WithOne(user => user.Profile)
            .HasForeignKey<UserProfileEntityBase>(profile => profile.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

internal sealed class UserProfileConfiguration<TProfile> : IEntityTypeConfiguration<UserProfileEntity<TProfile>>
{
    public void Configure(EntityTypeBuilder<UserProfileEntity<TProfile>> builder)
    {
        builder.ToTable("user_profiles");

        builder.Property(profile => profile.Profile)
            .HasColumnName("profile")
            .HasConversion(new JsonProfileConverter<TProfile>())
            .IsRequired();
    }

    private sealed class JsonProfileConverter<T>() : ValueConverter<T, string>(
        profile => JsonSerializer.Serialize(profile, JsonSerializerOptions.Default),
        json => JsonSerializer.Deserialize<T>(json, JsonSerializerOptions.Default)!);
}
