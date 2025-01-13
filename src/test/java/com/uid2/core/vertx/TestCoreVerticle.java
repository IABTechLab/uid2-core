package com.uid2.core.vertx;
import com.uid2.core.model.ConfigStore;
import com.uid2.core.model.SecretStore;
import com.uid2.core.service.*;
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
import com.uid2.shared.store.reader.RotatingCloudEncryptionKeyProvider;
import io.vertx.core.*;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.file.FileSystem;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;

import static com.uid2.core.Const.OPERATOR_CONFIG_PATH;
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
import java.io.ByteArrayInputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Callable;

import com.uid2.shared.model.CloudEncryptionKey;
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
    private RotatingCloudEncryptionKeyProvider cloudEncryptionKeyProvider;
    @Mock
    private FileSystem fileSystem;

    private AttestationService attestationService;
    private String operatorConfig;

    private static final String attestationProtocol = "test-attestation-protocol";
    private static final String attestationProtocolPublic = "trusted";
    @BeforeEach
    void deployVerticle(TestInfo info, Vertx vertx, VertxTestContext testContext) throws Throwable {
        JsonObject config = new JsonObject();
        config.put(Const.Config.OptOutUrlProp, "test_optout_url");
        config.put(Const.Config.CorePublicUrlProp, "test_core_url");
        config.put(Const.Config.AwsKmsJwtSigningKeyIdProp, "test_aws_kms_keyId");
        config.put(Const.Config.KeysetsMetadataPathProp, "keysets/metadata.json");
        config.put(Const.Config.encryptionSupportVersion, "2.6");
        if (info.getTags().contains("dontForceJwt")) {
            config.put(Const.Config.EnforceJwtProp, false);
        } else {
            config.put(Const.Config.EnforceJwtProp, true);
        }
        ConfigStore.Global.load(config);
        SecretStore.Global.load(config);

        attestationService = new AttestationService();
        MockitoAnnotations.initMocks(this);

        // Mock download method for different paths
        when(cloudStorage.download(anyString())).thenAnswer(invocation -> {
            String path = invocation.getArgument(0);
            System.out.println(path);
            if (path.contains("encrypted")) {
                return new ByteArrayInputStream("{ \"keysets\": { \"location\": \"encrypted-location\" } }".getBytes());
            } else {
                return new ByteArrayInputStream("{ \"keysets\": { \"location\": \"default-location\" } }".getBytes());
            }
        });

        // Mock preSignUrl method for different paths
        when(cloudStorage.preSignUrl(anyString())).thenAnswer(invocation -> {
            String path = invocation.getArgument(0);
            if (path.contains("encrypted")) {
                return new URL("http://encrypted_url");
            }else {
                return new URL("http://default_url");
            }
        });

        operatorConfig = Files.readString(Paths.get(OPERATOR_CONFIG_PATH)).trim();

        when(fileSystem.readFile(anyString(), any())).thenAnswer(invocation -> {
            String path = invocation.getArgument(0);
            Handler<AsyncResult<Buffer>> handler = invocation.getArgument(1);
            if (Objects.equals(path, OPERATOR_CONFIG_PATH)) {
                handler.handle(Future.succeededFuture(Buffer.buffer(operatorConfig)));
            } else {
                handler.handle(Future.failedFuture(new RuntimeException("Failed to read file: " + path)));
            }
            return null;
        });

        CoreVerticle verticle = new CoreVerticle(cloudStorage, authProvider, attestationService, attestationTokenService, enclaveIdentifierProvider, operatorJWTTokenProvider, jwtService, cloudEncryptionKeyProvider, fileSystem, OPERATOR_CONFIG_PATH);
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

    private void getWithVersion(Vertx vertx, String endpoint, MultiMap headers, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
        WebClient client = WebClient.create(vertx);
        client.getAbs(getUrlForEndpoint(endpoint))
                .putHeaders(headers)
                .send(handler);
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
    void wrongMethodForEndpointCloudEncryption(Vertx vertx, VertxTestContext testContext) {
        post(vertx, "/cloud_encryption_keys/retrieve", makeAttestationRequestJson(null, null), ar -> {
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
    void cloudEncryptionKeyRetrieveSuccess(Vertx vertx, VertxTestContext testContext) {
        fakeAuth(attestationProtocolPublic, Role.OPERATOR);
        addAttestationProvider(attestationProtocolPublic);
        onHandleAttestationRequest(() -> {
            byte[] resultPublicKey = null;
            return Future.succeededFuture(new AttestationResult(resultPublicKey, "test"));
        });

        CloudEncryptionKey key = new CloudEncryptionKey(1, 88, 1687635529, 1687808329, "newSecret");

        List<CloudEncryptionKey> keys = Arrays.asList(key);
        when(cloudEncryptionKeyProvider.getKeys(88)).thenReturn(keys);

        get(vertx, "cloud_encryption_keys/retrieve", ar -> {
            try {
                if (ar.succeeded()) {
                    HttpResponse<Buffer> response = ar.result();
                    assertEquals(200, response.statusCode());

                    JsonObject json = response.bodyAsJsonObject();
                    JsonArray cloudEncryptionKeysArray = json.getJsonArray("cloud_encryption_keys");

                    assertNotNull(cloudEncryptionKeysArray);
                    assertEquals(1, cloudEncryptionKeysArray.size());

                    JsonObject cloudEncryptionKeyJson = cloudEncryptionKeysArray.getJsonObject(0);
                    assertEquals(1, cloudEncryptionKeyJson.getInteger("id"));
                    assertEquals(88, cloudEncryptionKeyJson.getInteger("siteId"));
                    assertEquals(1687635529, cloudEncryptionKeyJson.getLong("activates"));
                    assertEquals(1687808329, cloudEncryptionKeyJson.getLong("created"));
                    assertEquals("newSecret", cloudEncryptionKeyJson.getString("secret"));

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
    void cloudEncryptionKeyRetrieveSuccessWithThreeKeys(Vertx vertx, VertxTestContext testContext) {
        fakeAuth(attestationProtocolPublic, Role.OPERATOR);
        addAttestationProvider(attestationProtocolPublic);
        onHandleAttestationRequest(() -> {
            byte[] resultPublicKey = null;
            return Future.succeededFuture(new AttestationResult(resultPublicKey, "test"));
        });

        // Create 3 CloudEncryptionKey objects
        CloudEncryptionKey key1 = new CloudEncryptionKey(1, 88, 1687635529, 1687808329, "secret1");
        CloudEncryptionKey key2 = new CloudEncryptionKey(2, 88, 1687635530, 1687808330, "secret2");
        CloudEncryptionKey key3 = new CloudEncryptionKey(3, 88, 1687635531, 1687808331, "secret3");

        List<CloudEncryptionKey> keys = Arrays.asList(key1, key2, key3);
        when(cloudEncryptionKeyProvider.getKeys(88)).thenReturn(keys);

        get(vertx, "cloud_encryption_keys/retrieve", ar -> {
            try {
                if (ar.succeeded()) {
                    HttpResponse<Buffer> response = ar.result();
                    assertEquals(200, response.statusCode());

                    JsonObject json = response.bodyAsJsonObject();
                    JsonArray cloudEncryptionKeysArray = json.getJsonArray("cloud_encryption_keys");

                    assertNotNull(cloudEncryptionKeysArray);
                    assertEquals(3, cloudEncryptionKeysArray.size());

                    for (int i = 0; i < 3; i++) {
                        JsonObject cloudEncryptionKeyJson = cloudEncryptionKeysArray.getJsonObject(i);
                        assertEquals(i + 1, cloudEncryptionKeyJson.getInteger("id"));
                        assertEquals(88, cloudEncryptionKeyJson.getInteger("siteId"));
                        assertEquals(1687635529 + i, cloudEncryptionKeyJson.getLong("activates"));
                        assertEquals(1687808329 + i, cloudEncryptionKeyJson.getLong("created"));
                        assertEquals("secret" + (i + 1), cloudEncryptionKeyJson.getString("secret"));
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
    void cloudEncryptionKeyRetrieveNoKeysOrError(Vertx vertx, VertxTestContext testContext) {
        fakeAuth(attestationProtocolPublic, Role.OPERATOR);
        addAttestationProvider(attestationProtocolPublic);
        onHandleAttestationRequest(() -> {
            byte[] resultPublicKey = null;
            return Future.succeededFuture(new AttestationResult(resultPublicKey, "test"));
        });

        // Test case 1: No keys found
        when(cloudEncryptionKeyProvider.getKeys(anyInt())).thenReturn(Collections.emptyList());

        get(vertx, "cloud_encryption_keys/retrieve", ar -> {
            try {
                if (ar.succeeded()) {
                    HttpResponse<Buffer> response = ar.result();
                    assertEquals(500, response.statusCode());

                    JsonObject json = response.bodyAsJsonObject();
                    assertEquals("No Cloud Encryption keys found", json.getString("status"));
                    assertTrue(json.getString("message").contains("No Cloud Encryption keys found for siteId:"));

                    // Test case 2: Exception thrown
                    when(cloudEncryptionKeyProvider.getKeys(anyInt())).thenThrow(new RuntimeException("Test exception"));

                    get(vertx, "cloud_encryption_keys/retrieve", ar2 -> {
                        if (ar2.succeeded()) {
                            HttpResponse<Buffer> response2 = ar2.result();
                            assertEquals(500, response2.statusCode());

                            JsonObject json2 = response2.bodyAsJsonObject();
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

    @Tag("dontForceJwt")
    @Test
    void keysetRefreshSuccessHigherVersion(Vertx vertx, VertxTestContext testContext) throws Exception {
        fakeAuth(attestationProtocolPublic, Role.OPERATOR);
        addAttestationProvider(attestationProtocolPublic);
        onHandleAttestationRequest(() -> {
            byte[] resultPublicKey = null;
            return Future.succeededFuture(new AttestationResult(resultPublicKey, "test"));
        });

        MultiMap headers = MultiMap.caseInsensitiveMultiMap();
        headers.add(Const.Http.AppVersionHeader, "uid2-operator=3.7.16-SNAPSHOT;uid2-attestation-api=1.1.0;uid2-shared=2.7.0-3e279acefa");

        getWithVersion(vertx, "key/keyset/refresh", headers, ar -> {
            assertTrue(ar.succeeded());
            if (ar.succeeded()) {
                HttpResponse<Buffer> response = ar.result();
                assertEquals(200, response.statusCode());
                String responseBody = response.bodyAsString();
                System.out.println(responseBody);
                assertEquals("{\"keysets\":{\"location\":\"http://encrypted_url\"}}", responseBody);
                testContext.completeNow();
            } else {
                testContext.failNow(ar.cause());
            }
        });
    }

    @Tag("dontForceJwt")
    @Test
    void keysRefreshSuccessLowerVersion(Vertx vertx, VertxTestContext testContext) throws Exception {
        fakeAuth(attestationProtocolPublic, Role.OPERATOR);
        addAttestationProvider(attestationProtocolPublic);
        onHandleAttestationRequest(() -> {
            byte[] resultPublicKey = null;
            return Future.succeededFuture(new AttestationResult(resultPublicKey, "test"));
        });

        MultiMap headers = MultiMap.caseInsensitiveMultiMap();
        headers.add(Const.Http.AppVersionHeader, "uid2-operator=2.1.16-SNAPSHOT;uid2-attestation-api=1.1.0;uid2-shared=2.7.0-3e279acefa");

        getWithVersion(vertx, "key/keyset/refresh", headers, ar -> {
            if (ar.succeeded()) {
                HttpResponse<Buffer> response = ar.result();
                System.out.println(response.bodyAsString());
                assertEquals(200, response.statusCode());
                String responseBody = response.bodyAsString();
                assertEquals("{\"keysets\":{\"location\":\"http://default_url\"}}", responseBody);
                testContext.completeNow();
            } else {
                testContext.failNow(ar.cause());
            }
        });
    }

    @Tag("dontForceJwt")
    @Test
    void keysRefreshSuccessNoHeaderVersion(Vertx vertx, VertxTestContext testContext) throws Exception {
        fakeAuth(attestationProtocolPublic, Role.OPERATOR);
        addAttestationProvider(attestationProtocolPublic);
        onHandleAttestationRequest(() -> {
            byte[] resultPublicKey = null;
            return Future.succeededFuture(new AttestationResult(resultPublicKey, "test"));
        });

        MultiMap headers = MultiMap.caseInsensitiveMultiMap();

        getWithVersion(vertx, "key/keyset/refresh", headers, ar -> {
            if (ar.succeeded()) {
                HttpResponse<Buffer> response = ar.result();
                System.out.println(response.bodyAsString());
                assertEquals(200, response.statusCode());
                String responseBody = response.bodyAsString();
                assertEquals("{\"keysets\":{\"location\":\"http://default_url\"}}", responseBody);
                testContext.completeNow();
            } else {
                testContext.failNow(ar.cause());
            }
        });
    }

    @Test
    void getConfigSuccess(Vertx vertx, VertxTestContext testContext) {
        JsonObject expectedConfig = new JsonObject(operatorConfig);

        fakeAuth(Role.OPERATOR);

        // Make HTTP Get request to operator config endpoint
        this.get(vertx, Endpoints.OPERATOR_CONFIG.toString(), testContext.succeeding(response -> testContext.verify(() -> {
                        assertEquals(200, response.statusCode());
                        assertEquals("application/json", response.getHeader(HttpHeaders.CONTENT_TYPE));
                        JsonObject actualConfig = new JsonObject(response.bodyAsString());
                        assertEquals(expectedConfig, actualConfig);
                        testContext.completeNow();
                    })
        ));
    }

    @Test
    void getConfigInvalidJson(Vertx vertx, VertxTestContext testContext) {
        operatorConfig = "invalid config";

        fakeAuth(Role.OPERATOR);

        this.get(vertx, Endpoints.OPERATOR_CONFIG.toString(), testContext.succeeding(response -> testContext.verify(() -> {
                    assertEquals(500, response.statusCode());
                    testContext.completeNow();
                })
        ));
    }
}
