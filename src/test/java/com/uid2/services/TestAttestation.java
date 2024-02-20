package com.uid2.services;

import com.uid2.shared.secure.AttestationFailure;
import com.uid2.shared.secure.AttestationResult;
import com.uid2.shared.secure.ICertificateProvider;
import com.uid2.shared.secure.NitroCoreAttestationService;
import com.uid2.shared.secure.nitro.InMemoryAWSCertificateStore;
import com.uid2.core.service.AttestationService;
import com.uid2.shared.attest.AttestationToken;
import com.uid2.shared.attest.AttestationTokenService;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class TestAttestation {

    @Test
    public void testGenerateAttestationToken()
    {
        final String userToken = "example-user-token";
        final String encryptionKey = "enc-key";
        final String encryptionSalt = "enc-salt";

        AttestationTokenService tokenService = new AttestationTokenService(encryptionKey, encryptionSalt, 86400);
        String encryptedTokenString = tokenService.createToken(userToken).getEncodedAttestationToken();

        AttestationToken token = AttestationToken.fromEncrypted(
            encryptedTokenString,
            encryptionKey,
            encryptionSalt);

        assertTrue(token.validate(userToken));
        assertFalse(token.validate("incorrect-user-token"));
    }

    @Test
    public void testExpiredAttestationToken()
    {
        final String userToken = "example-user-token";
        final String encryptionKey = "enc-key";
        final String encryptionSalt = "enc-salt";

        AttestationTokenService tokenService = new AttestationTokenService(encryptionKey, encryptionSalt, 1000);
        String encryptedTokenString = tokenService.createToken(
            userToken,
            Instant.now().minusSeconds(60));

        AttestationToken token = AttestationToken.fromEncrypted(
            encryptedTokenString,
            encryptionKey,
            encryptionSalt);

        // expiration
        assertFalse(token.validate(userToken));
    }

    @Test
    public void testNitroAttestation() throws Exception
    {
        final String identifierString = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        final String protocol = "aws-nitro";
        final ICertificateProvider certStore = new InMemoryAWSCertificateStore();

        AttestationService attestationService = new AttestationService()
            .with(protocol, new NitroCoreAttestationService(certStore, "https://core.local/"));

        // -- id check - disabled because certs in attestation request can expire. TODO: fix it
        /*attestationService.attest(protocol, nitroAttestationRequest, nitroPublicKey, ar -> {
            assertTrue(ar.succeeded());
            AttestationResult result = ar.result();
            assertFalse(result.isSuccess(), "attestation succeed with unregistered enclave id");
            assertEquals(AttestationFailure.FORBIDDEN_ENCLAVE.explain(), result.getReason(), "attestation failed with wrong reason.");
        });*/

        attestationService.registerEnclave(protocol, identifierString);

        // -- success path - disabled because certs in attestation request can expire. TODO: fix it
        /*attestationService.attest(protocol, nitroAttestationRequest, nitroPublicKey, ar -> {
            assertTrue(ar.succeeded());
            AttestationResult result = ar.result();
            assertTrue(result.isSuccess(), "failing on success path");
        });*/

        // -- MitM attack
        byte[] mess = nitroAttestationRequest.getBytes(StandardCharsets.UTF_8);
        mess[3] += 1;
        String messedRequest = new String(mess);

        attestationService.attest(protocol, messedRequest, "", ar -> {
            assertTrue(ar.succeeded());
            AttestationResult result = ar.result();
            assertFalse(result.isSuccess(), "succeeding on a messed-up att request");
            assertEquals(AttestationFailure.BAD_PAYLOAD.explain(), result.getReason(), "attestation failed with wrong reason");
        });

        // -- Mismatching public key
        String bogusPublicKey = Base64.getEncoder().encodeToString("bogus".getBytes(StandardCharsets.UTF_8));
        attestationService.attest(protocol, messedRequest, bogusPublicKey, ar -> {
            assertTrue(ar.succeeded());
            AttestationResult result = ar.result();
            assertFalse(result.isSuccess(), "succeeding on mismatched public key in request");
            assertEquals(AttestationFailure.BAD_PAYLOAD.explain(), result.getReason(), "attestation failed with wrong reason");
        });

        // -- cannot validate cert path
        class BadCertStore implements ICertificateProvider {
            @Override
            public X509Certificate getRootCertificate() {
                return null;
            }
        }

        AttestationService badCertAttestationService = new AttestationService()
                .with(protocol, new NitroCoreAttestationService(new BadCertStore(), "https://core.local/"));
        badCertAttestationService.attest(protocol, nitroAttestationRequest, "", ar -> {
            assertTrue(ar.succeeded());
            AttestationResult result = ar.result();
            assertFalse(result.isSuccess(), "succeeding before certificate (chain) is validated");
            assertEquals(AttestationFailure.BAD_CERTIFICATE.explain(), result.getReason(), "attestation failed with wrong reason");
        });

        attestationService.unregisterEnclave(protocol, identifierString);

        // -- unregistered enclave - disabled because certs in attestation request can expire. TODO: fix it
        /*attestationService.attest(protocol, nitroAttestationRequest, nitroPublicKey, ar -> {
            assertTrue(ar.succeeded());
            AttestationResult result = ar.result();
            assertFalse(result.isSuccess(), "attestation succeed with unregistered enclave id");
            assertEquals(AttestationFailure.FORBIDDEN_ENCLAVE.explain(), result.getReason(), "attestation failed with wrong reason.");
        });*/
    }

    private static final String nitroAttestationRequest = "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";
}
