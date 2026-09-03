using System.Buffers.Binary;
using System.Buffers.Text;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using Skopka.Identity.Errors;
using Skopka.Identity.Infrastructure.WebAuthn;
using Skopka.Identity.WebAuthn;
using Xunit;

namespace Skopka.Identity.Infrastructure.Tests;

/// <summary>
/// The ceremonies are exercised against an authenticator built here, because a
/// captured response from a real one is a single fixed challenge, origin and
/// key — it proves the happy path once and nothing about what has to be
/// refused. Every check the verifier makes is a test that changes exactly one
/// thing about an otherwise valid response.
/// </summary>
public sealed class WebAuthnCeremonyVerifierTests
{
    private const string RelyingParty = "skopi.club";
    private const string Origin = "https://skopi.club";

    private static readonly string[] Origins = [Origin];

    private readonly WebAuthnCeremonyVerifier verifier = new();

    [Fact]
    public void ReadsAnEllipticCurveRegistration()
    {
        var authenticator = Authenticator.WithEllipticCurveKey();
        var challenge = Challenge();

        var result = verifier.ReadRegistration(
            ClientData("webauthn.create", challenge, Origin),
            authenticator.Attestation(counter: 0),
            Expect(challenge));

        Assert.True(result.IsSuccess);
        Assert.Equal(WebAuthnAlgorithm.Es256, result.Value.Algorithm);
        Assert.Equal(authenticator.CredentialId, result.Value.CredentialId.ToArray());
        Assert.Equal(authenticator.AuthenticatorId, result.Value.AuthenticatorId);
        Assert.Equal(0, result.Value.SignatureCounter);
        Assert.True(result.Value.UserVerified);
    }

    [Fact]
    public void ReadsAnRsaRegistration()
    {
        var authenticator = Authenticator.WithRsaKey();
        var challenge = Challenge();

        var result = verifier.ReadRegistration(
            ClientData("webauthn.create", challenge, Origin),
            authenticator.Attestation(counter: 0),
            Expect(challenge));

        Assert.True(result.IsSuccess);
        Assert.Equal(WebAuthnAlgorithm.Rs256, result.Value.Algorithm);
    }

    /// <summary>
    /// The key that comes back out of a registration is the key that verifies
    /// the assertions of that credential. Nothing else in this library would
    /// notice if the two disagreed.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void VerifiesAnAssertionMadeByTheRegisteredKey(bool ellipticCurve)
    {
        var authenticator = ellipticCurve
            ? Authenticator.WithEllipticCurveKey()
            : Authenticator.WithRsaKey();
        var registration = verifier.ReadRegistration(
            ClientData("webauthn.create", Challenge(out var enrolled), Origin),
            authenticator.Attestation(counter: 0),
            Expect(enrolled));
        Assert.True(registration.IsSuccess);

        var challenge = Challenge();
        var clientData = ClientData("webauthn.get", challenge, Origin);
        var assertion = authenticator.Assert(clientData, counter: 4);

        var result = verifier.VerifyAssertion(
            clientData,
            assertion.AuthenticatorData,
            assertion.Signature,
            Assertion(challenge, registration.Value, known: 3));

        Assert.True(result.IsSuccess);
        Assert.Equal(4, result.Value.SignatureCounter);
    }

    [Fact]
    public void RefusesAChallengeItDidNotIssue()
    {
        var authenticator = Authenticator.WithEllipticCurveKey();
        var clientData = ClientData("webauthn.create", Challenge(), Origin);

        var result = verifier.ReadRegistration(
            clientData,
            authenticator.Attestation(counter: 0),
            Expect(Challenge()));

        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.WebAuthnChallengeMismatch);
    }

    [Fact]
    public void RefusesAnOriginItDoesNotServe()
    {
        var authenticator = Authenticator.WithEllipticCurveKey();
        var challenge = Challenge();

        var result = verifier.ReadRegistration(
            ClientData("webauthn.create", challenge, "https://skopi.club.example"),
            authenticator.Attestation(counter: 0),
            Expect(challenge));

        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.WebAuthnOriginNotAllowed);
    }

    [Fact]
    public void RefusesAnAuthenticatorAnsweringForAnotherRelyingParty()
    {
        var authenticator = Authenticator.WithEllipticCurveKey("skopi.example");
        var challenge = Challenge();

        var result = verifier.ReadRegistration(
            ClientData("webauthn.create", challenge, Origin),
            authenticator.Attestation(counter: 0),
            Expect(challenge));

        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.WebAuthnRelyingPartyMismatch);
    }

    [Fact]
    public void RefusesARegistrationResponseOfferedAsAnAssertion()
    {
        var authenticator = Authenticator.WithEllipticCurveKey();
        var registration = verifier.ReadRegistration(
            ClientData("webauthn.create", Challenge(out var enrolled), Origin),
            authenticator.Attestation(counter: 0),
            Expect(enrolled));
        Assert.True(registration.IsSuccess);

        var challenge = Challenge();
        var clientData = ClientData("webauthn.create", challenge, Origin);
        var assertion = authenticator.Assert(clientData, counter: 1);

        var result = verifier.VerifyAssertion(
            clientData,
            assertion.AuthenticatorData,
            assertion.Signature,
            Assertion(challenge, registration.Value, known: 0));

        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.WebAuthnCeremonyMismatch);
    }

    [Fact]
    public void RefusesAnAuthenticatorThatOnlyReportsPresence()
    {
        var authenticator = Authenticator.WithEllipticCurveKey();
        var challenge = Challenge();

        var result = verifier.ReadRegistration(
            ClientData("webauthn.create", challenge, Origin),
            authenticator.Attestation(counter: 0, userVerified: false),
            Expect(challenge));

        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.WebAuthnUserNotVerified);
    }

    [Fact]
    public void RefusesAnAuthenticatorThatReportsNobodyAtAll()
    {
        var authenticator = Authenticator.WithEllipticCurveKey();
        var challenge = Challenge();

        var result = verifier.ReadRegistration(
            ClientData("webauthn.create", challenge, Origin),
            authenticator.Attestation(counter: 0, userPresent: false),
            Expect(challenge));

        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.WebAuthnUserNotPresent);
    }

    [Fact]
    public void RefusesASignatureOverSomethingElse()
    {
        var authenticator = Authenticator.WithEllipticCurveKey();
        var registration = verifier.ReadRegistration(
            ClientData("webauthn.create", Challenge(out var enrolled), Origin),
            authenticator.Attestation(counter: 0),
            Expect(enrolled));
        Assert.True(registration.IsSuccess);

        var challenge = Challenge();
        var clientData = ClientData("webauthn.get", challenge, Origin);
        var assertion = authenticator.Assert(clientData, counter: 1);
        var tampered = assertion.Signature.ToArray();
        tampered[^1] ^= 0xFF;

        var result = verifier.VerifyAssertion(
            clientData,
            assertion.AuthenticatorData,
            tampered,
            Assertion(challenge, registration.Value, known: 0));

        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.WebAuthnSignatureInvalid);
    }

    /// <summary>
    /// A counter that stands still or goes backwards is how a cloned
    /// authenticator gives itself away.
    /// </summary>
    [Theory]
    [InlineData(7L, 7L)]
    [InlineData(7L, 6L)]
    public void RefusesACounterThatDidNotAdvance(long known, long reported)
    {
        var authenticator = Authenticator.WithEllipticCurveKey();
        var registration = verifier.ReadRegistration(
            ClientData("webauthn.create", Challenge(out var enrolled), Origin),
            authenticator.Attestation(counter: 0),
            Expect(enrolled));
        Assert.True(registration.IsSuccess);

        var challenge = Challenge();
        var clientData = ClientData("webauthn.get", challenge, Origin);
        var assertion = authenticator.Assert(clientData, reported);

        var result = verifier.VerifyAssertion(
            clientData,
            assertion.AuthenticatorData,
            assertion.Signature,
            Assertion(challenge, registration.Value, known));

        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.WebAuthnCounterRegressed);
    }

    /// <summary>
    /// An authenticator that keeps no counter reports zero for ever, and the
    /// specification says to accept that rather than to read it as a clone.
    /// </summary>
    [Fact]
    public void AcceptsAStandingZeroFromAnAuthenticatorThatDoesNotCount()
    {
        var authenticator = Authenticator.WithEllipticCurveKey();
        var registration = verifier.ReadRegistration(
            ClientData("webauthn.create", Challenge(out var enrolled), Origin),
            authenticator.Attestation(counter: 0),
            Expect(enrolled));
        Assert.True(registration.IsSuccess);

        var challenge = Challenge();
        var clientData = ClientData("webauthn.get", challenge, Origin);
        var assertion = authenticator.Assert(clientData, counter: 0);

        var result = verifier.VerifyAssertion(
            clientData,
            assertion.AuthenticatorData,
            assertion.Signature,
            Assertion(challenge, registration.Value, known: 0));

        Assert.True(result.IsSuccess);
    }

    /// <summary>
    /// Refused while registering rather than stored and refused at every
    /// sign-in afterwards.
    /// </summary>
    [Fact]
    public void RefusesAnAlgorithmItCannotVerify()
    {
        var authenticator = Authenticator.WithEllipticCurveKey();
        var challenge = Challenge();

        var result = verifier.ReadRegistration(
            ClientData("webauthn.create", challenge, Origin),
            authenticator.Attestation(counter: 0, algorithm: -8),
            Expect(challenge));

        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.WebAuthnAlgorithmNotSupported);
    }

    [Fact]
    public void RefusesClientDataThatIsNotJson()
    {
        var authenticator = Authenticator.WithEllipticCurveKey();

        var result = verifier.ReadRegistration(
            "not json"u8.ToArray(),
            authenticator.Attestation(counter: 0),
            Expect(Challenge()));

        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.WebAuthnClientDataInvalid);
    }

    [Fact]
    public void RefusesAnAttestationObjectThatIsNotCbor()
    {
        var challenge = Challenge();

        var result = verifier.ReadRegistration(
            ClientData("webauthn.create", challenge, Origin),
            "not cbor"u8.ToArray(),
            Expect(challenge));

        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.WebAuthnAttestationInvalid);
    }

    private static byte[] Challenge() => RandomNumberGenerator.GetBytes(32);

    private static byte[] Challenge(out byte[] issued)
    {
        issued = Challenge();
        return issued;
    }

    private static WebAuthnCeremonyExpectation Expect(byte[] challenge)
        => new(RelyingParty, Origins, challenge, UserVerificationRequired: true);

    private static WebAuthnAssertionExpectation Assertion(
        byte[] challenge,
        WebAuthnAttestedCredential credential,
        long? known)
        => new(
            RelyingParty,
            Origins,
            challenge,
            UserVerificationRequired: true,
            credential.PublicKey,
            credential.Algorithm,
            known);

    private static byte[] ClientData(string type, byte[] challenge, string origin)
        => Encoding.UTF8.GetBytes(
            $$"""
            {"type":"{{type}}","challenge":"{{Base64Url.EncodeToString(challenge)}}","origin":"{{origin}}","crossOrigin":false}
            """);

    /// <summary>
    /// Everything an authenticator does, in the order the wire format puts it.
    /// </summary>
    private sealed class Authenticator
    {
        private readonly ECDsa? ellipticCurve;
        private readonly RSA? rsa;
        private readonly string relyingParty;

        private Authenticator(string relyingParty, ECDsa? ellipticCurve, RSA? rsa)
        {
            this.relyingParty = relyingParty;
            this.ellipticCurve = ellipticCurve;
            this.rsa = rsa;
        }

        public byte[] CredentialId { get; } = RandomNumberGenerator.GetBytes(32);

        public Guid AuthenticatorId { get; } = Guid.NewGuid();

        public static Authenticator WithEllipticCurveKey(
            string relyingParty = RelyingParty)
            => new(
                relyingParty,
                ECDsa.Create(ECCurve.NamedCurves.nistP256),
                null);

        public static Authenticator WithRsaKey(string relyingParty = RelyingParty)
            => new(relyingParty, null, RSA.Create(2048));

        public byte[] Attestation(
            long counter,
            bool userPresent = true,
            bool userVerified = true,
            long? algorithm = null)
        {
            var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
            writer.WriteStartMap(3);
            writer.WriteTextString("fmt");
            writer.WriteTextString("none");
            writer.WriteTextString("attStmt");
            writer.WriteStartMap(0);
            writer.WriteEndMap();
            writer.WriteTextString("authData");
            writer.WriteByteString(
                AuthenticatorData(counter, userPresent, userVerified, algorithm));
            writer.WriteEndMap();
            return writer.Encode();
        }

        public (byte[] AuthenticatorData, byte[] Signature) Assert(
            byte[] clientDataJson,
            long counter,
            bool userPresent = true,
            bool userVerified = true)
        {
            var data = Header(counter, userPresent, userVerified);
            var signed = new byte[data.Length + SHA256.HashSizeInBytes];
            data.CopyTo(signed, 0);
            SHA256.HashData(clientDataJson, signed.AsSpan(data.Length));
            var signature = ellipticCurve is not null
                ? ellipticCurve.SignData(
                    signed,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.Rfc3279DerSequence)
                : rsa!.SignData(
                    signed,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
            return (data, signature);
        }

        private byte[] Header(long counter, bool userPresent, bool userVerified)
        {
            var data = new byte[37];
            SHA256.HashData(Encoding.UTF8.GetBytes(relyingParty), data);
            data[32] = (byte)(
                (userPresent ? 0b0000_0001 : 0)
                | (userVerified ? 0b0000_0100 : 0));
            BinaryPrimitives.WriteUInt32BigEndian(
                data.AsSpan(33),
                (uint)counter);
            return data;
        }

        private byte[] AuthenticatorData(
            long counter,
            bool userPresent,
            bool userVerified,
            long? algorithm)
        {
            var header = Header(counter, userPresent, userVerified);
            // The attested-credential flag, which is what says the credential
            // and its key follow the header.
            header[32] |= 0b0100_0000;
            var key = CoseKey(algorithm);
            var data = new byte[header.Length + 16 + 2 + CredentialId.Length + key.Length];
            header.CopyTo(data, 0);
            AuthenticatorId.TryWriteBytes(data.AsSpan(header.Length, 16), bigEndian: true, out _);
            BinaryPrimitives.WriteUInt16BigEndian(
                data.AsSpan(header.Length + 16),
                (ushort)CredentialId.Length);
            CredentialId.CopyTo(data, header.Length + 18);
            key.CopyTo(data, header.Length + 18 + CredentialId.Length);
            return data;
        }

        private byte[] CoseKey(long? algorithm)
        {
            var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
            if (ellipticCurve is not null)
            {
                var parameters = ellipticCurve.ExportParameters(false);
                writer.WriteStartMap(5);
                writer.WriteInt32(1);
                writer.WriteInt32(2);
                writer.WriteInt32(3);
                writer.WriteInt64(algorithm ?? -7);
                writer.WriteInt32(-1);
                writer.WriteInt32(1);
                writer.WriteInt32(-2);
                writer.WriteByteString(parameters.Q.X!);
                writer.WriteInt32(-3);
                writer.WriteByteString(parameters.Q.Y!);
                writer.WriteEndMap();
            }
            else
            {
                var parameters = rsa!.ExportParameters(false);
                writer.WriteStartMap(4);
                writer.WriteInt32(1);
                writer.WriteInt32(3);
                writer.WriteInt32(3);
                writer.WriteInt64(algorithm ?? -257);
                writer.WriteInt32(-1);
                writer.WriteByteString(parameters.Modulus!);
                writer.WriteInt32(-2);
                writer.WriteByteString(parameters.Exponent!);
                writer.WriteEndMap();
            }

            return writer.Encode();
        }
    }
}
