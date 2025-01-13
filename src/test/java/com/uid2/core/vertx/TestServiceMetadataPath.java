package com.uid2.core.vertx;

import com.uid2.core.model.ConfigStore;
import com.uid2.core.model.SecretStore;
import com.uid2.core.service.AttestationService;
import com.uid2.core.service.OperatorJWTTokenProvider;
import com.uid2.shared.Const;
import com.uid2.shared.attest.IAttestationTokenService;
import com.uid2.shared.attest.JwtService;
import com.uid2.shared.auth.IAuthorizableProvider;
import com.uid2.shared.auth.IEnclaveIdentifierProvider;
import com.uid2.shared.auth.OperatorKey;
import com.uid2.shared.auth.OperatorType;
import com.uid2.shared.cloud.CloudStorageException;
import com.uid2.shared.cloud.ICloudStorage;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.file.FileSystem;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.io.StringBufferInputStream;
import java.net.URL;
import java.util.HashSet;

import static com.uid2.core.Const.OPERATOR_CONFIG_PATH;
import static com.uid2.shared.Utils.readToEndAsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(VertxExtension.class)
public class TestServiceMetadataPath {
    @Mock
    private ICloudStorage cloudStorage;
    @Mock
    private IAuthorizableProvider authProvider;
    @Mock
    private IAttestationTokenService attestationTokenService;
    @Mock
    private IEnclaveIdentifierProvider enclaveIdentifierProvider;

    private AttestationService attestationService;
    private FileSystem fileSystem;

    @Mock
    private OperatorJWTTokenProvider operatorJWTTokenProvider;
    @Mock
    private JwtService jwtService;

    // we need trusted to skip the attestation procedure or otherwise the core encpoint call made in this file will
    // fail at the attestation handler
    private static final String attestationProtocol = "trusted";

    @BeforeEach
    void deployVerticle(Vertx vertx, VertxTestContext testContext) throws Throwable {
        JsonObject config = new JsonObject();
        config.put(Const.Config.EnforceJwtProp, false);
        ConfigStore.Global.load(config);

        attestationService = new AttestationService();
        fileSystem = vertx.fileSystem();
        SecretStore.Global.load(((JsonObject) Json.decodeValue(openFile("/com.uid2.core/testGlobalMetadata/test-secrets.json"))));
        MockitoAnnotations.initMocks(this);
        CoreVerticle verticle = new CoreVerticle(cloudStorage, authProvider, attestationService, attestationTokenService, enclaveIdentifierProvider, operatorJWTTokenProvider, jwtService, fileSystem, OPERATOR_CONFIG_PATH);
        vertx.deployVerticle(verticle, testContext.succeeding(id -> testContext.completeNow()));
    }

    private String getUrlForEndpoint(String endpoint) {
        return String.format("http://127.0.0.1:%d/%s", Const.Port.ServicePortForCore, endpoint);
    }

    private void fakeAuth(OperatorType operatorType, int siteId) {
        OperatorKey operatorKey = new OperatorKey("test-key-hash", "test-key-salt", "", "", attestationProtocol, 0, false, siteId, new HashSet<>(), operatorType,  "test-key-id");
        when(authProvider.get(any())).thenReturn(operatorKey);
    }

    private void get(Vertx vertx, String endpoint, String body, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
        WebClient client = WebClient.create(vertx);
        client.getAbs(getUrlForEndpoint(endpoint)).sendBuffer(Buffer.buffer(body), handler);
    }

    @Test
    void publicOperatorGetsGlobalKeypairs(Vertx vertx, VertxTestContext testContext) throws CloudStorageException, IOException {
        String metadata = "/com.uid2.core/testGlobalMetadata/services/metadata.json";
        String metadataContent = openFile(metadata);
        String location = ((JsonObject) Json.decodeValue(metadataContent)).getJsonObject("services").getString("location");
        when(cloudStorage.download(eq(metadata))).thenReturn(new StringBufferInputStream(metadataContent));
        when(cloudStorage.preSignUrl(any())).thenAnswer(i -> new URL(i.getArgument(0)));
        fakeAuth(OperatorType.PUBLIC, 99);
        get(vertx, "/services/refresh", "", testContext.succeeding(response -> testContext.verify(() -> {
            assertEquals(200, response.statusCode());
            JsonObject json = response.bodyAsJsonObject();
            String resultLocation = json.getJsonObject("services").getString("location");
            assertEquals(resultLocation, location);
            testContext.completeNow();
        })));
    }

    @Test
    void privateOperatorGetsKeypairsError(Vertx vertx, VertxTestContext testContext) throws CloudStorageException, IOException {
        String metadata = "/com.uid2.core/testGlobalMetadata/services/metadata.json";
        String metadataContent = openFile(metadata);
        String location = ((JsonObject) Json.decodeValue(metadataContent)).getJsonObject("services").getString("location");
        when(cloudStorage.download(eq(metadata))).thenReturn(new StringBufferInputStream(metadataContent));
        when(cloudStorage.preSignUrl(any())).thenAnswer(i -> new URL(i.getArgument(0)));
        fakeAuth(OperatorType.PRIVATE, 99);
        get(vertx, "/services/refresh", "", testContext.succeeding(response -> testContext.verify(() -> {
            assertEquals(403, response.statusCode());
            assertEquals("endpoint /services/refresh is for public operators only", response.bodyAsJsonObject().getString("message"));
            testContext.completeNow();
        })));
    }

    String openFile(String filePath) throws IOException {
        return readToEndAsString(TestSiteSpecificMetadataPath.class.getResourceAsStream(filePath));
    }
}
