package com.uid2.core.vertx;

import com.uid2.core.model.ConfigStore;
import com.uid2.core.service.AttestationService;
import com.uid2.core.service.JWTTokenProvider;
import com.uid2.core.service.OperatorJWTTokenProvider;
import com.uid2.shared.Const;
import com.uid2.shared.attest.EncryptedAttestationToken;
import com.uid2.shared.attest.IAttestationTokenService;
import com.uid2.shared.attest.JwtService;
import com.uid2.shared.auth.*;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.secure.AttestationException;
import com.uid2.shared.secure.AttestationFailure;
import com.uid2.shared.secure.AttestationResult;
import com.uid2.shared.secure.ICoreAttestationService;
import com.uid2.shared.store.reader.RotatingS3KeyProvider;
import io.vertx.core.*;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Callable;

import com.uid2.shared.model.S3Key;
import java.util.Arrays;

import static org.mockito.Mockito.*;

@ExtendWith(VertxExtension.class)
public class TestCoreVerticle {
    @Mock
    private ICloudStorage cloudStorage;
    @Mock
    private IAuthorizableProvider authProvider;
    @Mock
    private ICoreAttestationService attestationProvider;
    @Mock
    private IAttestationTokenService attestationTokenService;
    @Mock
    private IEnclaveIdentifierProvider enclaveIdentifierProvider;
    @Mock
    private OperatorJWTTokenProvider operatorJWTTokenProvider;
    @Mock
    private JwtService jwtService;
    @Mock
    private RotatingS3KeyProvider s3KeyProvider;

    private AttestationService attestationService;

    private static final String attestationProtocol = "test-attestation-protocol";
    private static final String attestationProtocolPublic = "trusted";

    @BeforeEach
    void deployVerticle(TestInfo info, Vertx vertx, VertxTestContext testContext) throws Throwable {
        JsonObject config = new JsonObject();
        config.put(Const.Config.OptOutUrlProp, "test_optout_url");
        config.put(Const.Config.CorePublicUrlProp, "test_core_url");
        config.put(Const.Config.AwsKmsJwtSigningKeyIdProp, "test_aws_kms_keyId");
        if (info.getTags().contains("dontForceJwt")) {
            config.put(Const.Config.EnforceJwtProp, false);
        } else {
            config.put(Const.Config.EnforceJwtProp, true);
        }
        ConfigStore.Global.load(config);

        attestationService = new AttestationService();
        MockitoAnnotations.initMocks(this);

        CoreVerticle verticle = new CoreVerticle(cloudStorage, authProvider, attestationService, attestationTokenService, enclaveIdentifierProvider, operatorJWTTokenProvider, jwtService, s3KeyProvider);
        vertx.deployVerticle(verticle, testContext.succeeding(id -> testContext.completeNow()));
    }

    private String getUrlForEndpoint(String endpoint) {
        return String.format("http://127.0.0.1:%d/%s", Const.Port.ServicePortForCore, endpoint);
    }

    private void fakeAuth(Role... roles) {
        this.fakeAuth(attestationProtocol, roles);
    }

    private void fakeAuth(String attestationProtocol, String operatorType, Role... roles) {
        if (operatorType.isEmpty()) {
            operatorType = "PRIVATE";
        }
        OperatorKey operatorKey = new OperatorKey("test-key-hash", "test-key-salt", "test-name", "test-contact", attestationProtocol, 0, false, 88, new HashSet<>(Arrays.asList(roles)), OperatorType.valueOf(operatorType.toUpperCase()), "test-key-id");
        when(authProvider.get(any())).thenReturn(operatorKey);
    }

    private void fakeAuth(String attestationProtocol, Role... roles) {
        fakeAuth(attestationProtocol, "private", roles);
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

    private void post(Vertx vertx, String endpoint, MultiMap form, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
        WebClient client = WebClient.create(vertx);
        client.postAbs(getUrlForEndpoint(endpoint)).putHeader("content-type", "multipart/form-data").sendForm(form, handler);
    }

    private void get(Vertx vertx, String endpoint, MultiMap form, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
        WebClient client = WebClient.create(vertx);
        client.getAbs(getUrlForEndpoint(endpoint)).putHeader("content-type", "multipart/form-data").sendForm(form, handler);
    }

    private void get(Vertx vertx, String endpoint, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
        WebClient client = WebClient.create(vertx);
        client.getAbs(getUrlForEndpoint(endpoint)).send(handler);
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

    private static String makeAttestationRequestJson(String attestationRequest, String publicKey, String operatorType) {
        JsonObject json = new JsonObject();
        if (!operatorType.isEmpty()) {
            json.put("operator_type", operatorType);
        }
        if (attestationRequest != null) {
            json.put("attestation_request", attestationRequest);
        }
        if (publicKey != null) {
            json.put("public_key", publicKey);
        }
        return json.toString();
    }

    private static String makeAttestationRequestJson(String attestationRequest, String publicKey) {
        return makeAttestationRequestJson(attestationRequest, publicKey, "");
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
            assertEquals(403, response.statusCode());
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

    @ParameterizedTest
    @EnumSource(value = AttestationFailure.class, names = {"UNKNOWN_ATTESTATION_URL", "FORBIDDEN_ENCLAVE", "BAD_FORMAT", "INVALID_PROTOCOL", "BAD_CERTIFICATE", "BAD_PAYLOAD"})
    void attestFailureWithResultClientError(AttestationFailure failure, Vertx vertx, VertxTestContext testContext) {
        fakeAuth(Role.OPERATOR);
        addAttestationProvider(attestationProtocol);
        onHandleAttestationRequest(() -> {
            return Future.succeededFuture(new AttestationResult(failure));
        });
        post(vertx, "attest", makeAttestationRequestJson("xxx", "yyy"), ar -> {
            try {
                assertTrue(ar.succeeded());
                HttpResponse response = ar.result();
                assertEquals(403, response.statusCode());
                testContext.completeNow();
            } catch (Throwable ex) {
                testContext.failNow(ex);
            }
        });
    }

    @ParameterizedTest
    @EnumSource(value = AttestationFailure.class, names = {"UNKNOWN", "INTERNAL_ERROR"})
    void attestFailureWithResultServerError(AttestationFailure failure, Vertx vertx, VertxTestContext testContext) {
        fakeAuth(Role.OPERATOR);
        addAttestationProvider(attestationProtocol);
        onHandleAttestationRequest(() -> {
            return Future.succeededFuture(new AttestationResult(failure));
        });
        post(vertx, "attest", makeAttestationRequestJson("xxx", "yyy"), ar -> {
            try {
                assertTrue(ar.succeeded());
                HttpResponse response = ar.result();
                assertEquals(500, response.statusCode());
                testContext.completeNow();
            } catch (Throwable ex) {
                testContext.failNow(ex);
            }
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"public", "private", "PUBLIC", "PRIVATE", ""})
    void attestSuccessNoEncryption(String operatorType, Vertx vertx, VertxTestContext testContext) {
        fakeAuth(attestationProtocol, operatorType, Role.OPERATOR);
        addAttestationProvider(attestationProtocol);
        onHandleAttestationRequest(() -> {
            byte[] resultPublicKey = null;
            return Future.succeededFuture(new AttestationResult(resultPublicKey, "test"));
        });
        EncryptedAttestationToken encryptedAttestationToken = new EncryptedAttestationToken("test-attestation-token", Instant.ofEpochMilli(111));
        when(attestationTokenService.createToken(any())).thenReturn(encryptedAttestationToken);
        post(vertx, "attest", makeAttestationRequestJson("xxx", "yyy"), ar -> {
            try {
                assertTrue(ar.succeeded());
                HttpResponse response = ar.result();
                assertEquals(200, response.statusCode());
                JsonObject json = response.bodyAsJsonObject();
                String attestationToken = json.getJsonObject("body").getString("attestation_token");
                String expiresAt = json.getJsonObject("body").getString("expiresAt");
                assertEquals("test-attestation-token", attestationToken);
                assertEquals("1970-01-01T00:00:00.111Z", expiresAt);
                testContext.completeNow();
            } catch (Throwable ex) {
                testContext.failNow(ex);
            }
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"public", "private", "PUBLIC", "PRIVATE"})
    void attestOperatorTypeMismatchNoEncryption(String operatorType, Vertx vertx, VertxTestContext testContext) {
        fakeAuth(attestationProtocol, operatorType, Role.OPERATOR);
        addAttestationProvider(attestationProtocol);
        onHandleAttestationRequest(() -> {
            byte[] resultPublicKey = null;
            return Future.succeededFuture(new AttestationResult(resultPublicKey, "test"));
        });
        EncryptedAttestationToken encryptedAttestationToken = new EncryptedAttestationToken("test-attestation-token", Instant.ofEpochMilli(111));
        when(attestationTokenService.createToken(any())).thenReturn(encryptedAttestationToken);
        post(vertx, "attest", makeAttestationRequestJson("xxx", "yyy", operatorType.equalsIgnoreCase("public") ? "private" : "public"), ar -> {
            try {
                assertTrue(ar.succeeded());
                HttpResponse response = ar.result();
                assertEquals(403, response.statusCode());
                JsonObject json = response.bodyAsJsonObject();
                assertEquals("attestation failure; invalid operator type", json.getString("status"));
                testContext.completeNow();
            } catch (Throwable ex) {
                testContext.failNow(ex);
            }
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"public", "private", "PUBLIC", "PRIVATE", ""})
    void attestSuccessWithEncryption(String operatorType, Vertx vertx, VertxTestContext testContext) throws Throwable {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(Const.Name.AsymetricEncryptionKeyClass);
        gen.initialize(2048, new SecureRandom());
        KeyPair keyPair = gen.generateKeyPair();
        byte[] publicKey = keyPair.getPublic().getEncoded();

        fakeAuth(attestationProtocol, operatorType, Role.OPERATOR);
        addAttestationProvider(attestationProtocol);
        onHandleAttestationRequest(() -> {
            return Future.succeededFuture(new AttestationResult(publicKey, "test"));
        });
        EncryptedAttestationToken encryptedAttestationToken = new EncryptedAttestationToken("test-attestation-token", Instant.ofEpochMilli(111));
        when(attestationTokenService.createToken(any())).thenReturn(encryptedAttestationToken);
        post(vertx, "attest", makeAttestationRequestJson("xxx", "yyy", operatorType), ar -> {
            try {
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
            } catch (Throwable ex) {
                testContext.failNow(ex);
            }
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"public", "private", "PUBLIC", "PRIVATE", ""})
    void attestOperatorTypeMismatchWithEncryption(String operatorType, Vertx vertx, VertxTestContext testContext) throws Throwable {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(Const.Name.AsymetricEncryptionKeyClass);
        gen.initialize(2048, new SecureRandom());
        KeyPair keyPair = gen.generateKeyPair();
        byte[] publicKey = keyPair.getPublic().getEncoded();

        fakeAuth(attestationProtocol, operatorType, Role.OPERATOR);

        addAttestationProvider(attestationProtocol);
        onHandleAttestationRequest(() -> {
            return Future.succeededFuture(new AttestationResult(publicKey, "test"));
        });
        EncryptedAttestationToken encryptedAttestationToken = new EncryptedAttestationToken("test-attestation-token", Instant.ofEpochMilli(111));
        when(attestationTokenService.createToken(any())).thenReturn(encryptedAttestationToken);
        post(vertx, "attest", makeAttestationRequestJson("xxx", "yyy", operatorType.equalsIgnoreCase("public") ? "private" : "public"), ar -> {
            try {
                assertTrue(ar.succeeded());
                HttpResponse response = ar.result();
                assertEquals(403, response.statusCode());
                JsonObject json = response.bodyAsJsonObject();
                assertEquals("attestation failure; invalid operator type", json.getString("status"));
                testContext.completeNow();
            } catch (Throwable ex) {
                testContext.failNow(ex);
            }
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
            try {
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
            } catch (Throwable ex) {
                testContext.failNow(ex);
            }
        });
    }

    @Test
    void attestOptOutJWTCalledUnknownClient(Vertx vertx, VertxTestContext testContext) throws Throwable {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(Const.Name.AsymetricEncryptionKeyClass);
        gen.initialize(2048, new SecureRandom());
        KeyPair keyPair = gen.generateKeyPair();
        byte[] publicKey = keyPair.getPublic().getEncoded();

        fakeAuth(Role.OPERATOR, Role.OPTOUT);
        addAttestationProvider(attestationProtocol);
        onHandleAttestationRequest(() -> {
            return Future.succeededFuture(new AttestationResult(publicKey, "test-enclaveId"));
        });
        EncryptedAttestationToken encryptedAttestationToken = new EncryptedAttestationToken("test-attestation-token", Instant.ofEpochMilli(111));
        when(attestationTokenService.createToken(any())).thenReturn(encryptedAttestationToken);
        when(operatorJWTTokenProvider.getOptOutJWTToken("test-key-hash", "test-name", Set.of(Role.OPERATOR, Role.OPTOUT), 88, "test-enclaveId", attestationProtocol, "unknown client version", Instant.ofEpochMilli(111))).thenReturn("dummy_token_optout");
        when(operatorJWTTokenProvider.getCoreJWTToken("test-key-hash", "test-name", Set.of(Role.OPERATOR, Role.OPTOUT), 88, "test-enclaveId", attestationProtocol, "unknown client version", Instant.ofEpochMilli(111))).thenReturn("dummy_token_core");
        post(vertx, "attest", makeAttestationRequestJson("xxx", null), ar -> {
            try {
                assertTrue(ar.succeeded());
                HttpResponse response = ar.result();

                try {
                    verify(operatorJWTTokenProvider, times(1)).getCoreJWTToken("test-key-hash", "test-name", Set.of(Role.OPERATOR, Role.OPTOUT), 88, "test-enclaveId", attestationProtocol, "unknown client version", Instant.ofEpochMilli(111));
                    verify(operatorJWTTokenProvider, times(1)).getOptOutJWTToken("test-key-hash", "test-name", Set.of(Role.OPERATOR, Role.OPTOUT), 88, "test-enclaveId", attestationProtocol, "unknown client version", Instant.ofEpochMilli(111));
                    JsonObject json = response.bodyAsJsonObject();
                    String jwtOptout = json.getJsonObject("body").getString("attestation_jwt_optout");
                    String jwtCore = json.getJsonObject("body").getString("attestation_jwt_core");
                    assertEquals("dummy_token_optout", jwtOptout);
                    assertEquals("dummy_token_core", jwtCore);
                } catch (Exception e) {
                    testContext.failNow(e);
                }

                testContext.completeNow();
            } catch (Throwable ex) {
                testContext.failNow(ex);
            }
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
        when(operatorJWTTokenProvider.getCoreJWTToken("test-key-hash", "test-name", Set.of(Role.OPERATOR), 88, "test-enclaveId", attestationProtocol, "test-contact|uid2-operator|2.7.16-SNAPSHOT", Instant.ofEpochMilli(111))).thenReturn("dummy_token_core");

        MultiMap map = MultiMap.caseInsensitiveMultiMap();
        map.add(Const.Http.AppVersionHeader, "uid2-operator=2.7.16-SNAPSHOT;uid2-attestation-api=1.1.0;uid2-shared=2.7.0-3e279acefa");

        post(vertx, "attest", makeAttestationRequestJson("xxx", null), map, ar -> {
            assertTrue(ar.succeeded());
            HttpResponse response = ar.result();

            try {
                verify(operatorJWTTokenProvider, times(1)).getCoreJWTToken("test-key-hash", "test-name", Set.of(Role.OPERATOR), 88, "test-enclaveId", attestationProtocol, "test-contact|uid2-operator|2.7.16-SNAPSHOT", Instant.ofEpochMilli(111));
                JsonObject json = response.bodyAsJsonObject();
                String jwt = json.getJsonObject("body").getString("attestation_jwt_core");
                assertEquals("dummy_token_core", jwt);
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

        when(operatorJWTTokenProvider.getCoreJWTToken(anyString(), anyString(), any(), anyInt(), anyString(), any(), anyString(), any())).thenThrow(new JWTTokenProvider(null, null).new JwtSigningException(Optional.of("Test error")));
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

    @Test
    void multipartRequestWrongMethodForMultipart(Vertx vertx, VertxTestContext testContext) {
        MultiMap form = MultiMap.caseInsensitiveMultiMap();
        form.set("firstValue", "value1");
        form.set("secondValue", "value2");

        get(vertx, "/sites/refresh", form, (ar) -> {
            try {
                HttpResponse response = ar.result();
                assertEquals(400, response.statusCode());
                assertEquals("Content-Type \"multipart/*\" Not Allowed\"", response.bodyAsString());
                testContext.completeNow();
            } catch (Throwable ex) {
                testContext.failNow(ex);
            }
        });
    }

    @Test
    void multipartRequestWrongMethodForEndpoint(Vertx vertx, VertxTestContext testContext) {
        MultiMap form = MultiMap.caseInsensitiveMultiMap();
        form.set("firstValue", "value1");
        form.set("secondValue", "value2");

        post(vertx, "/sites/refresh", form, (ar) -> {
            try {
                HttpResponse response = ar.result();
                assertEquals(405, response.statusCode());
                assertEquals("Method Not Allowed", response.statusMessage());
                testContext.completeNow();
            } catch (Throwable ex) {
                testContext.failNow(ex);
            }
        });
    }

    @Test
    void wrongMethodForEndpoint(Vertx vertx, VertxTestContext testContext) {
        post(vertx, "/sites/refresh", makeAttestationRequestJson(null, null), ar -> {
            try {
                HttpResponse response = ar.result();
                assertEquals(405, response.statusCode());
                assertEquals("Method Not Allowed", response.statusMessage());
                testContext.completeNow();
            } catch (Throwable ex) {
                testContext.failNow(ex);
            }
        });
    }

    @Test
    void wrongMethodForEndpointS3(Vertx vertx, VertxTestContext testContext) {
        post(vertx, "/s3encryption_keys/retrieve", makeAttestationRequestJson(null, null), ar -> {
            try {
                HttpResponse response = ar.result();
                assertEquals(405, response.statusCode());
                assertEquals("Method Not Allowed", response.statusMessage());
                testContext.completeNow();
            } catch (Throwable ex) {
                testContext.failNow(ex);
            }
        });
    }

    @Tag("dontForceJwt")
    @Test
    void s3encryptionKeyRetrieveSuccess(Vertx vertx, VertxTestContext testContext) {
        fakeAuth(attestationProtocolPublic, Role.OPERATOR);
        addAttestationProvider(attestationProtocolPublic);
        onHandleAttestationRequest(() -> {
            byte[] resultPublicKey = null;
            return Future.succeededFuture(new AttestationResult(resultPublicKey, "test"));
        });

        S3Key key = new S3Key(1, 88, 1687635529, 1687808329, "newSecret");

        List<S3Key> keys = Arrays.asList(key);
        when(s3KeyProvider.getKeys(88)).thenReturn(keys);

        get(vertx, "s3encryption_keys/retrieve", ar -> {
            try {
                if (ar.succeeded()) {
                    HttpResponse<Buffer> response = ar.result();
                    assertEquals(200, response.statusCode());

                    JsonObject json = response.bodyAsJsonObject();
                    JsonArray s3KeysArray = json.getJsonArray("s3Keys");

                    assertNotNull(s3KeysArray);
                    assertEquals(1, s3KeysArray.size());

                    JsonObject s3KeyJson = s3KeysArray.getJsonObject(0);
                    assertEquals(1, s3KeyJson.getInteger("id"));
                    assertEquals(88, s3KeyJson.getInteger("siteId"));
                    assertEquals(1687635529, s3KeyJson.getLong("activates"));
                    assertEquals(1687808329, s3KeyJson.getLong("created"));
                    assertEquals("newSecret", s3KeyJson.getString("secret"));

                    testContext.completeNow();
                } else {
                    testContext.failNow(ar.cause());
                }
            } catch (Throwable ex) {
                testContext.failNow(ex);
            }
        });
    }


    @Tag("dontForceJwt")
    @Test
    void s3encryptionKeyRetrieveSuccessWithThreeKeys(Vertx vertx, VertxTestContext testContext) {
        fakeAuth(attestationProtocolPublic, Role.OPERATOR);
        addAttestationProvider(attestationProtocolPublic);
        onHandleAttestationRequest(() -> {
            byte[] resultPublicKey = null;
            return Future.succeededFuture(new AttestationResult(resultPublicKey, "test"));
        });

        // Create 3 S3Key objects
        S3Key key1 = new S3Key(1, 88, 1687635529, 1687808329, "secret1");
        S3Key key2 = new S3Key(2, 88, 1687635530, 1687808330, "secret2");
        S3Key key3 = new S3Key(3, 88, 1687635531, 1687808331, "secret3");

        List<S3Key> keys = Arrays.asList(key1, key2, key3);
        when(s3KeyProvider.getKeys(88)).thenReturn(keys);

        get(vertx, "s3encryption_keys/retrieve", ar -> {
            try {
                if (ar.succeeded()) {
                    HttpResponse<Buffer> response = ar.result();
                    assertEquals(200, response.statusCode());

                    JsonObject json = response.bodyAsJsonObject();
                    JsonArray s3KeysArray = json.getJsonArray("s3Keys");

                    assertNotNull(s3KeysArray);
                    assertEquals(3, s3KeysArray.size());

                    for (int i = 0; i < 3; i++) {
                        JsonObject s3KeyJson = s3KeysArray.getJsonObject(i);
                        assertEquals(i + 1, s3KeyJson.getInteger("id"));
                        assertEquals(88, s3KeyJson.getInteger("siteId"));
                        assertEquals(1687635529 + i, s3KeyJson.getLong("activates"));
                        assertEquals(1687808329 + i, s3KeyJson.getLong("created"));
                        assertEquals("secret" + (i + 1), s3KeyJson.getString("secret"));
                    }

                    testContext.completeNow();
                } else {
                    testContext.failNow(ar.cause());
                }
            } catch (Throwable ex) {
                testContext.failNow(ex);
            }
        });
    }

    @Tag("dontForceJwt")
    @Test
    void s3encryptionKeyRetrieveNoKeysOrError(Vertx vertx, VertxTestContext testContext) {
        fakeAuth(attestationProtocolPublic, Role.OPERATOR);
        addAttestationProvider(attestationProtocolPublic);
        onHandleAttestationRequest(() -> {
            byte[] resultPublicKey = null;
            return Future.succeededFuture(new AttestationResult(resultPublicKey, "test"));
        });

        // Test case 1: No keys found
        when(s3KeyProvider.getKeys(anyInt())).thenReturn(Collections.emptyList());

        get(vertx, "s3encryption_keys/retrieve", ar -> {
            try {
                if (ar.succeeded()) {
                    HttpResponse<Buffer> response = ar.result();
                    assertEquals(500, response.statusCode());

                    JsonObject json = response.bodyAsJsonObject();
                    assertEquals("No S3 keys found", json.getString("status"));
                    assertTrue(json.getString("message").contains("No S3 keys found for siteId:"));

                    // Test case 2: Exception thrown
                    when(s3KeyProvider.getKeys(anyInt())).thenThrow(new RuntimeException("Test exception"));

                    get(vertx, "s3encryption_keys/retrieve", ar2 -> {
                        if (ar2.succeeded()) {
                            HttpResponse<Buffer> response2 = ar2.result();
                            assertEquals(500, response2.statusCode());

                            JsonObject json2 = response2.bodyAsJsonObject();
                            System.out.println(json2);
                            assertEquals("error", json2.getString("status"));
                            assertEquals("error generating attestation token", json2.getString("message"));

                            testContext.completeNow();
                        } else {
                            testContext.failNow(ar2.cause());
                        }
                    });
                } else {
                    testContext.failNow(ar.cause());
                }
            } catch (Throwable ex) {
                testContext.failNow(ex);
            }
        });
    }
}
