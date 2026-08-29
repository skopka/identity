using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Skopka.Identity.DeviceAuthorization;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Sessions;

namespace Skopka.Identity.Ef.Configurations;

internal sealed class DeviceAuthorizationRequestConfiguration
    : IEntityTypeConfiguration<DeviceAuthorizationRequestEntity>
{
    public void Configure(
        EntityTypeBuilder<DeviceAuthorizationRequestEntity> builder)
    {
        builder.ToTable("device_authorization_requests");
        builder.HasKey(request => request.Id);

        builder.Property(request => request.Id).HasColumnName("id");
        builder.Property(request => request.DeviceCode)
            .HasColumnName("device_code")
            .HasMaxLength(DeviceAuthorizationLimits.MaximumDeviceCodeLength)
            .IsRequired();
        builder.Property(request => request.BrowserVerifierHash)
            .HasColumnName("browser_verifier_hash")
            .HasMaxLength(DeviceAuthorizationLimits.VerifierHashLength)
            .IsRequired();
        builder.Property(request => request.UserCode)
            .HasColumnName("user_code")
            .HasMaxLength(DeviceAuthorizationLimits.MaximumUserCodeLength)
            .IsRequired();
        builder.Property(request => request.State)
            .HasColumnName("state");
        builder.Property(request => request.IpAddress)
            .HasColumnName("ip_address")
            .HasMaxLength(DeviceAuthorizationLimits.MaximumIpAddressLength);
        builder.Property(request => request.UserAgent)
            .HasColumnName("user_agent")
            .HasMaxLength(DeviceAuthorizationLimits.MaximumUserAgentLength);
        builder.Property(request => request.DeviceDisplayName)
            .HasColumnName("device_display_name")
            .HasMaxLength(
                DeviceAuthorizationLimits.MaximumDeviceDisplayNameLength);
        builder.Property(request => request.ClientId)
            .HasColumnName("client_id")
            .HasMaxLength(DeviceAuthorizationLimits.MaximumClientIdLength);
        builder.Property(request => request.ReturnUrl)
            .HasColumnName("return_url")
            .HasMaxLength(DeviceAuthorizationLimits.MaximumReturnUrlLength);
        builder.Property(request => request.SessionClientName)
            .HasColumnName("session_client_name")
            .HasMaxLength(SessionLimits.MaximumClientNameLength);
        builder.Property(request => request.SessionDeviceName)
            .HasColumnName("session_device_name")
            .HasMaxLength(SessionLimits.MaximumDeviceNameLength);
        builder.Property(request => request.ResolvedByUserId)
            .HasColumnName("resolved_by_user_id");
        builder.Property(request => request.ApprovedSecurityStamp)
            .HasColumnName("approved_security_stamp")
            .HasMaxLength(SessionLimits.SecurityStampLength);
        builder.Property(request => request.ConsumptionId)
            .HasColumnName("consumption_id");
        builder.Property(request => request.SessionId)
            .HasColumnName("session_id");
        builder.Property(request => request.Version)
            .HasColumnName("version")
            .IsConcurrencyToken();
        builder.Property(request => request.CreatedAt)
            .HasColumnName("created_at");
        builder.Property(request => request.ExpiresAt)
            .HasColumnName("expires_at");
        builder.Property(request => request.ModifiedAt)
            .HasColumnName("modified_at");
        builder.Property(request => request.ResolvedAt)
            .HasColumnName("resolved_at");
        builder.Property(request => request.ConsumedAt)
            .HasColumnName("consumed_at");

        builder.HasIndex(request => request.DeviceCode)
            .IsUnique()
            .HasDatabaseName(
                "ux_device_authorization_requests_device_code");
        builder.HasIndex(request => new
            {
                request.State,
                request.ExpiresAt,
            })
            .HasDatabaseName(
                "ix_device_authorization_requests_state_expires_at");
    }
}
