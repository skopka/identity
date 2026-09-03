using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.WebAuthn;

namespace Skopka.Identity.Ef.Configurations;

internal sealed class WebAuthnCredentialConfiguration
    : IEntityTypeConfiguration<WebAuthnCredentialEntity>
{
    public void Configure(EntityTypeBuilder<WebAuthnCredentialEntity> builder)
    {
        builder.ToTable("user_webauthn_credentials");
        builder.HasKey(credential => credential.Id);

        builder.Property(credential => credential.Id).HasColumnName("id");
        builder.Property(credential => credential.UserId).HasColumnName("user_id");
        builder.Property(credential => credential.CredentialId)
            .HasColumnName("credential_id")
            .HasMaxLength(WebAuthnLimits.MaximumCredentialIdLength)
            .IsRequired();
        builder.Property(credential => credential.PublicKey)
            .HasColumnName("public_key")
            .HasMaxLength(WebAuthnLimits.MaximumPublicKeyLength)
            .IsRequired();
        builder.Property(credential => credential.Algorithm)
            .HasColumnName("algorithm");
        builder.Property(credential => credential.SignatureCounter)
            .HasColumnName("signature_counter");
        builder.Property(credential => credential.AuthenticatorId)
            .HasColumnName("authenticator_id");
        builder.Property(credential => credential.BackedUp)
            .HasColumnName("backed_up");
        builder.Property(credential => credential.Label)
            .HasColumnName("label")
            .HasMaxLength(WebAuthnLimits.MaximumLabelLength);
        builder.Property(credential => credential.Version)
            .HasColumnName("version")
            .IsConcurrencyToken();
        builder.Property(credential => credential.CreatedAt)
            .HasColumnName("created_at");
        builder.Property(credential => credential.LastUsedAt)
            .HasColumnName("last_used_at");

        // Across every user, not within one: an assertion arrives carrying a
        // credential id and nothing else, so the identifier has to name one row
        // in the table before it can name a user.
        builder.HasIndex(credential => credential.CredentialId)
            .IsUnique()
            .HasDatabaseName("ux_user_webauthn_credentials_credential_id");

        builder.HasIndex(credential => credential.UserId)
            .HasDatabaseName("ix_user_webauthn_credentials_user_id");

        builder.HasOne(credential => credential.User)
            .WithMany()
            .HasForeignKey(credential => credential.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
