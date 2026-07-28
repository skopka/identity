using System.Security.Cryptography;
using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Skopka.Identity.Sessions;

public sealed class HmacJwtAccessTokenProvider
    : IIdentityAccessTokenProvider, IDisposable
{
    private readonly byte[] signingKey;
    private readonly JsonWebTokenHandler handler;
    private readonly SigningCredentials signingCredentials;
    private readonly TokenValidationParameters validationParameters;
    private readonly string issuer;
    private readonly string audience;
    private bool disposed;

    public HmacJwtAccessTokenProvider(
        byte[] signingKey,
        JwtAccessTokenOptions options)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentNullException.ThrowIfNull(options);

        if (signingKey.Length < 32)
        {
            throw new ArgumentException(
                "The JWT signing key must contain at least 32 bytes.",
                nameof(signingKey));
        }

        this.signingKey = signingKey.ToArray();
        issuer = options.Issuer;
        audience = options.Audience;
        var securityKey = new SymmetricSecurityKey(this.signingKey);
        signingCredentials = new SigningCredentials(
            securityKey,
            SecurityAlgorithms.HmacSha256);
        validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = securityKey,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ValidateLifetime = true,
            ClockSkew = options.ClockSkew,
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            ValidTypes = ["JWT"],
        };
        handler = new JsonWebTokenHandler
        {
            MaximumTokenSizeInBytes = SessionLimits.MaximumTokenLength,
            SetDefaultTimesOnTokenCreation = false,
        };
    }

    public string Generate(IdentityAccessTokenPayload payload)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentNullException.ThrowIfNull(payload);

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            IssuedAt = payload.IssuedAt.UtcDateTime,
            NotBefore = payload.IssuedAt.UtcDateTime,
            Expires = payload.ExpiresAt.UtcDateTime,
            SigningCredentials = signingCredentials,
            Subject = new ClaimsIdentity(
                (payload.Claims ?? [])
                    .Select(CreateClaim)),
            Claims = new Dictionary<string, object>
            {
                [JwtRegisteredClaimNames.Sub] = payload.UserId.ToString("N"),
                [JwtRegisteredClaimNames.Jti] = payload.TokenId.ToString("N"),
                [IdentitySessionClaimTypes.SessionId] =
                    payload.SessionId.ToString("N"),
                [IdentitySessionClaimTypes.FormatVersion] =
                    payload.FormatVersion,
            },
        };

        var token = handler.CreateToken(descriptor);
        if (token.Length > SessionLimits.MaximumTokenLength)
        {
            throw new InvalidOperationException(
                "The generated access token exceeds the supported length.");
        }

        return token;
    }

    public async Task<IdentityAccessTokenPayload?> ValidateAsync(
        string token,
        CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ct.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(token)
            || token.Length > SessionLimits.MaximumTokenLength)
        {
            return null;
        }

        var result = await handler.ValidateTokenAsync(
            token,
            validationParameters);
        if (!result.IsValid
            || result.SecurityToken is not JsonWebToken jwt
            || !TryReadGuid(jwt, JwtRegisteredClaimNames.Jti, out var tokenId)
            || !TryReadGuid(jwt, JwtRegisteredClaimNames.Sub, out var userId)
            || !TryReadGuid(
                jwt,
                IdentitySessionClaimTypes.SessionId,
                out var sessionId)
            || !jwt.TryGetPayloadValue<int>(
                IdentitySessionClaimTypes.FormatVersion,
                out var formatVersion))
        {
            return null;
        }

        return new IdentityAccessTokenPayload(
            formatVersion,
            tokenId,
            userId,
            sessionId,
            new DateTimeOffset(jwt.ValidFrom, TimeSpan.Zero),
            new DateTimeOffset(jwt.ValidTo, TimeSpan.Zero),
            result.ClaimsIdentity.Claims
                .Where(claim => !ReservedClaimTypes.Contains(claim.Type))
                .Select(claim => new IdentitySessionClaim(
                    claim.Type,
                    claim.Value))
                .ToArray());
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        CryptographicOperations.ZeroMemory(signingKey);
    }

    internal TokenValidationParameters CreateTokenValidationParameters()
        => validationParameters.Clone();

    private static bool TryReadGuid(
        JsonWebToken jwt,
        string claim,
        out Guid value)
    {
        value = default;
        return jwt.TryGetPayloadValue<string>(claim, out var text)
            && Guid.TryParseExact(text, "N", out value);
    }

    private static Claim CreateClaim(IdentitySessionClaim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);

        if (string.IsNullOrWhiteSpace(claim.Type)
            || claim.Type.Length
                > IdentitySessionClaimLimits.MaximumTypeLength
            || claim.Value is null
            || claim.Value.Length
                > IdentitySessionClaimLimits.MaximumValueLength
            || ReservedClaimTypes.Contains(claim.Type))
        {
            throw new ArgumentException(
                "The access token contains an invalid custom claim.",
                nameof(claim));
        }

        var valueType = claim.Type is
            IdentitySessionClaimTypes.EmailVerified
            or IdentitySessionClaimTypes.PhoneNumberVerified
                ? ClaimValueTypes.Boolean
                : ClaimValueTypes.String;

        return new Claim(
            claim.Type,
            claim.Value,
            valueType);
    }

    private static readonly HashSet<string> ReservedClaimTypes =
        new(StringComparer.Ordinal)
        {
            JwtRegisteredClaimNames.Iss,
            JwtRegisteredClaimNames.Aud,
            JwtRegisteredClaimNames.Exp,
            JwtRegisteredClaimNames.Nbf,
            JwtRegisteredClaimNames.Iat,
            JwtRegisteredClaimNames.Jti,
            JwtRegisteredClaimNames.Sub,
            IdentitySessionClaimTypes.SessionId,
            IdentitySessionClaimTypes.FormatVersion,
        };
}
