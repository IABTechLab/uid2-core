package com.uid2.core.vertx;

import com.uid2.core.model.ConfigStore;
import com.uid2.core.service.AttestationService;
import com.uid2.core.service.JWTTokenProvider;
import com.uid2.core.service.OptOutJWTTokenProvider;
import com.uid2.shared.Const;
import com.uid2.shared.attest.EncryptedAttestationToken;
import com.uid2.shared.attest.IAttestationTokenService;
import com.uid2.shared.attest.JwtService;
import com.uid2.shared.auth.*;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.secure.AttestationException;
import com.uid2.shared.secure.AttestationFailure;
import com.uid2.shared.secure.AttestationResult;
import com.uid2.shared.secure.IAttestationProvider;
import io.vertx.core.*;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Dictionary;
import java.util.HashSet;
import java.util.Optional;
import java.util.concurrent.Callable;

import static org.mockito.Mockito.*;

@ExtendWith(VertxExtension.class)
public class TestCoreVerticle {
    @Mock
    private ICloudStorage cloudStorage;
    @Mock
    private IAuthorizableProvider authProvider;
    @Mock
    private IAttestationProvider attestationProvider;
    @Mock
    private IAttestationTokenService attestationTokenService;
    @Mock
    private IEnclaveIdentifierProvider enclaveIdentifierProvider;
    @Mock
    private OptOutJWTTokenProvider optOutJWTTokenProvider;
    @Mock
    private JwtService jwtService;

    private AttestationService attestationService;

    private static final String attestationProtocol = "test-attestation-protocol";

    @BeforeEach
    void deployVerticle(Vertx vertx, VertxTestContext testContext) throws Throwable {
        JsonObject config = new JsonObject();
        config.put(Const.Config.OptOutUrlProp, "test_optout_url");
        config.put(Const.Config.CorePublicUrlProp, "test_core_url");
        config.put(Const.Config.AwsKmsJwtSigningKeyIdProp, "test_aws_kms_keyId");
        config.put(Const.Config.EnforceJwtProp, false);
        ConfigStore.Global.load(config);

        attestationService = new AttestationService();
        MockitoAnnotations.initMocks(this);
        CoreVerticle verticle = new CoreVerticle(cloudStorage, authProvider, attestationService, attestationTokenService, enclaveIdentifierProvider, optOutJWTTokenProvider, jwtService);
        vertx.deployVerticle(verticle, testContext.succeeding(id -> testContext.completeNow()));
    }

    private String getUrlForEndpoint(String endpoint) {
        return String.format("http://127.0.0.1:%d/%s", Const.Port.ServicePortForCore, endpoint);
    }

    private void fakeAuth(Role role) {
        OperatorKey clientKey = new OperatorKey("test-key", "test-name", "test-contact", attestationProtocol, 0, false, 88, new HashSet<>(), OperatorType.PRIVATE);
        when(authProvider.get(any())).thenReturn(clientKey);
    }
    private void post(Vertx vertx, String endpoint, String body, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
        post(vertx, endpoint, body, null, handler);
    }
    private void post(Vertx vertx, String endpoint, String body, MultiMap multiMap, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
        WebClient client = WebClient.create(vertx);
        if (multiMap == null) {
            client.postAbs(getUrlForEndpoint(endpoint)).sendBuffer(Buffer.buffer(body), handler);
        } else {
            client.postAbs(getUrlForEndpoint(endpoint)).putHeaders(multiMap).sendBuffer(Buffer.buffer(body), handler);
        }
    }

    private void addAttestationProvider(String protocol) {
        attestationService.with(protocol, attestationProvider);
    }

    private void onHandleAttestationRequest(Callable<Future<AttestationResult>> f) {
        doAnswer(i -> {
            Handler<AsyncResult<AttestationResult>> handler = i.getArgument(2);
            handler.handle(f.call());
            return null;
        }).when(attestationProvider).attest(any(), any(), any());

    }

    private static String makeAttestationRequestJson(String attestationRequest, String publicKey) {
        JsonObject json = new JsonObject();
        if (attestationRequest != null) {
            json.put("attestation_request", attestationRequest);
        }
        if (publicKey != null) {
            json.put("public_key", publicKey);
        }
        return json.toString();
    }

    @Test
    void verticleDeployed(Vertx vertx, VertxTestContext testContext) {
        testContext.completeNow();
    }

    @Test
    void attestInvalidRequestBody(Vertx vertx, VertxTestContext testContext) {
        fakeAuth(Role.OPERATOR);
        addAttestationProvider(attestationProtocol);
        post(vertx, "attest", "blah", ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(400, response.statusCode());
            testContext.completeNow();
        });
    }

    @Test
    void attestNoAttestationRequestInBody(Vertx vertx, VertxTestContext testContext) {
        fakeAuth(Role.OPERATOR);
        addAttestationProvider(attestationProtocol);
        post(vertx, "attest", "{\"blah\": \"xxx\"}", ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(400, response.statusCode());
            testContext.completeNow();
        });
    }

    @Test
    void attestEmptyAttestationRequestInBody(Vertx vertx, VertxTestContext testContext) {
        fakeAuth(Role.OPERATOR);
        addAttestationProvider(attestationProtocol);
        post(vertx, "attest", makeAttestationRequestJson("", "yyy"), ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(400, response.statusCode());
            testContext.completeNow();
        });
    }

    @Test
    void attestUnknownAttestationProtocol(Vertx vertx, VertxTestContext testContext) {
        fakeAuth(Role.OPERATOR);
        addAttestationProvider("bogus-protocol");
        post(vertx, "attest", makeAttestationRequestJson("xxx", "yyy"), ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(500, response.statusCode());
            testContext.completeNow();
        });
    }

    @Test
    void attestFailureWithAnException(Vertx vertx, VertxTestContext testContext) {
        fakeAuth(Role.OPERATOR);
        addAttestationProvider(attestationProtocol);
        onHandleAttestationRequest(() -> {
            return Future.failedFuture(new AttestationException("test"));
        });
        post(vertx, "attest", makeAttestationRequestJson("xxx", "yyy"), ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(500, response.statusCode());
            testContext.completeNow();
        });
    }

    @Test
    void attestFailureWithResult(Vertx vertx, VertxTestContext testContext) {
        fakeAuth(Role.OPERATOR);
        addAttestationProvider(attestationProtocol);
        onHandleAttestationRequest(() -> {
            return Future.succeededFuture(new AttestationResult(AttestationFailure.BAD_PAYLOAD));
        });
        post(vertx, "attest", makeAttestationRequestJson("xxx", "yyy"), ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(401, response.statusCode());
            testContext.completeNow();
        });
    }

    @Test
    void attestSuccessNoEncryption(Vertx vertx, VertxTestContext testContext) {
        fakeAuth(Role.OPERATOR);
        addAttestationProvider(attestationProtocol);
        onHandleAttestationRequest(() -> {
            byte[] resultPublicKey = null;
            return Future.succeededFuture(new AttestationResult(resultPublicKey, "test"));
        });
        EncryptedAttestationToken encryptedAttestationToken = new EncryptedAttestationToken("test-attestation-token", Instant.ofEpochMilli(111));
        when(attestationTokenService.createToken(any())).thenReturn(encryptedAttestationToken);
        post(vertx, "attest", makeAttestationRequestJson("xxx", "yyy"), ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(200, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            String attestationToken = json.getJsonObject("body").getString("attestation_token");
            String expiresAt = json.getJsonObject("body").getString("expiresAt");
            assertEquals("test-attestation-token", attestationToken);
            assertEquals("1970-01-01T00:00:00.111Z", expiresAt);
            testContext.completeNow();
        });
    }

    @Test
    void attestSuccessWithEncryption(Vertx vertx, VertxTestContext testContext) throws Throwable {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(Const.Name.AsymetricEncryptionKeyClass);
        gen.initialize(2048, new SecureRandom());
        KeyPair keyPair = gen.generateKeyPair();
        byte[] publicKey = keyPair.getPublic().getEncoded();

        fakeAuth(Role.OPERATOR);
        addAttestationProvider(attestationProtocol);
        onHandleAttestationRequest(() -> {
            return Future.succeededFuture(new AttestationResult(publicKey, "test"));
        });
        EncryptedAttestationToken encryptedAttestationToken = new EncryptedAttestationToken("test-attestation-token", Instant.ofEpochMilli(111));
        when(attestationTokenService.createToken(any())).thenReturn(encryptedAttestationToken);
        post(vertx, "attest", makeAttestationRequestJson("xxx", "yyy"), ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(200, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            String attestationToken = json.getJsonObject("body").getString("attestation_token");
            assertNotEquals("", attestationToken);
            String expiresAt = json.getJsonObject("body").getString("expiresAt");
            assertEquals("1970-01-01T00:00:00.111Z", expiresAt);
            String[] decryptedAttestationToken = {""};
            assertDoesNotThrow(() -> {
                Cipher cipher = Cipher.getInstance(Const.Name.AsymetricEncryptionCipherClass);
                cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
                decryptedAttestationToken[0] = new String(cipher.doFinal(Base64.getDecoder().decode(attestationToken)));
            });

            assertEquals("test-attestation-token", decryptedAttestationToken[0]);

            testContext.completeNow();
        });
    }

    @Test
    void attestSuccessWithEncryptionNoPublicKeyOnRequest(Vertx vertx, VertxTestContext testContext) throws Throwable {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(Const.Name.AsymetricEncryptionKeyClass);
        gen.initialize(2048, new SecureRandom());
        KeyPair keyPair = gen.generateKeyPair();
        byte[] publicKey = keyPair.getPublic().getEncoded();

        fakeAuth(Role.OPERATOR);
        addAttestationProvider(attestationProtocol);
        onHandleAttestationRequest(() -> {
            return Future.succeededFuture(new AttestationResult(publicKey, "test"));
        });
        EncryptedAttestationToken encryptedAttestationToken = new EncryptedAttestationToken("test-attestation-token", Instant.ofEpochMilli(111));
        when(attestationTokenService.createToken(any())).thenReturn(encryptedAttestationToken);
        post(vertx, "attest", makeAttestationRequestJson("xxx", null), ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            assertEquals(200, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            String attestationToken = json.getJsonObject("body").getString("attestation_token");
            assertNotEquals("", attestationToken);
            String expiresAt = json.getJsonObject("body").getString("expiresAt");
            assertEquals("1970-01-01T00:00:00.111Z", expiresAt);

            String[] decryptedAttestationToken = {""};
            assertDoesNotThrow(() -> {
                Cipher cipher = Cipher.getInstance(Const.Name.AsymetricEncryptionCipherClass);
                cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
                decryptedAttestationToken[0] = new String(cipher.doFinal(Base64.getDecoder().decode(attestationToken)));
            });

            assertEquals("test-attestation-token", decryptedAttestationToken[0]);

            testContext.completeNow();
        });
    }

    @Test
    void attestOptOutJWTCalledUnknownClient(Vertx vertx, VertxTestContext testContext) throws Throwable {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(Const.Name.AsymetricEncryptionKeyClass);
        gen.initialize(2048, new SecureRandom());
        KeyPair keyPair = gen.generateKeyPair();
        byte[] publicKey = keyPair.getPublic().getEncoded();

        fakeAuth(Role.OPERATOR);
        addAttestationProvider(attestationProtocol);
        onHandleAttestationRequest(() -> {
            return Future.succeededFuture(new AttestationResult(publicKey, "test-enclaveId"));
        });
        EncryptedAttestationToken encryptedAttestationToken = new EncryptedAttestationToken("test-attestation-token", Instant.ofEpochMilli(111));
        when(attestationTokenService.createToken(any())).thenReturn(encryptedAttestationToken);
        HashSet<Role> expectedRoles = new HashSet<>();
        expectedRoles.add(Role.OPERATOR);
        when(optOutJWTTokenProvider.getOptOutJWTToken("test-name", expectedRoles, 88, "test-enclaveId", attestationProtocol, "unknown client", Instant.ofEpochMilli(111))).thenReturn("dummy_token");
        post(vertx, "attest", makeAttestationRequestJson("xxx", null), ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();

            try {
                verify(optOutJWTTokenProvider, times(1)).getOptOutJWTToken("test-name", expectedRoles, 88, "test-enclaveId", attestationProtocol, "unknown client", Instant.ofEpochMilli(111));
                JsonObject json = response.bodyAsJsonObject();
                String jwt = json.getJsonObject("body").getString("attestation_jwt");
            } catch (Exception e) {
                testContext.failNow(e);
            }

            testContext.completeNow();
        });
    }
    @Test
    void attestOptOutJWTCalledKnownClient(Vertx vertx, VertxTestContext testContext) throws Throwable {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(Const.Name.AsymetricEncryptionKeyClass);
        gen.initialize(2048, new SecureRandom());
        KeyPair keyPair = gen.generateKeyPair();
        byte[] publicKey = keyPair.getPublic().getEncoded();

        fakeAuth(Role.OPERATOR);
        addAttestationProvider(attestationProtocol);
        onHandleAttestationRequest(() -> {
            return Future.succeededFuture(new AttestationResult(publicKey, "test-enclaveId"));
        });
        EncryptedAttestationToken encryptedAttestationToken = new EncryptedAttestationToken("test-attestation-token", Instant.ofEpochMilli(111));
        when(attestationTokenService.createToken(any())).thenReturn(encryptedAttestationToken);
        HashSet<Role> expectedRoles = new HashSet<>();
        expectedRoles.add(Role.OPERATOR);
        when(optOutJWTTokenProvider.getOptOutJWTToken("test-name", expectedRoles, 88, "test-enclaveId", attestationProtocol, "test-contact|uid2-operator|2.7.16-SNAPSHOT", Instant.ofEpochMilli(111))).thenReturn("dummy_token");

        MultiMap map = MultiMap.caseInsensitiveMultiMap();
        map.add(Const.Http.AppVersionHeader, "uid2-operator=2.7.16-SNAPSHOT;uid2-attestation-api=1.1.0;uid2-shared=2.7.0-3e279acefa");

        post(vertx, "attest", makeAttestationRequestJson("xxx", null), map, ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();

            try {
                verify(optOutJWTTokenProvider, times(1)).getOptOutJWTToken("test-name", expectedRoles, 88, "test-enclaveId", attestationProtocol, "test-contact|uid2-operator|2.7.16-SNAPSHOT", Instant.ofEpochMilli(111));
                JsonObject json = response.bodyAsJsonObject();
                String jwt = json.getJsonObject("body").getString("attestation_jwt");
            } catch (Exception e) {
                testContext.failNow(e);
            }

            testContext.completeNow();
        });
    }

    @Test
    void attestOptOutJWTCalledReturns500OnError(Vertx vertx, VertxTestContext testContext) throws Throwable {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(Const.Name.AsymetricEncryptionKeyClass);
        gen.initialize(2048, new SecureRandom());
        KeyPair keyPair = gen.generateKeyPair();
        byte[] publicKey = keyPair.getPublic().getEncoded();

        fakeAuth(Role.OPERATOR);
        addAttestationProvider(attestationProtocol);
        onHandleAttestationRequest(() -> {
            return Future.succeededFuture(new AttestationResult(publicKey, "test-enclaveId"));
        });
        EncryptedAttestationToken encryptedAttestationToken = new EncryptedAttestationToken("test-attestation-token", Instant.ofEpochMilli(111));
        when(attestationTokenService.createToken(any())).thenReturn(encryptedAttestationToken);

        when(optOutJWTTokenProvider.getOptOutJWTToken(anyString(), any(), anyInt(), anyString(), any(), anyString(), any())).thenThrow(new JWTTokenProvider(null, null).new JwtSigningException(Optional.of("Test error")));
        post(vertx, "attest", makeAttestationRequestJson("xxx", null), ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();
            try {
                assertEquals(500, response.statusCode());
                assertEquals("Internal Server Error", response.statusMessage());
            } catch (Throwable e) {
                testContext.failNow(e);
            }

            testContext.completeNow();
        });
    }
}
