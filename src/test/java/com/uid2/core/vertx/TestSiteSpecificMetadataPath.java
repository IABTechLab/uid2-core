package com.uid2.core.vertx;

import com.uid2.core.model.SecretStore;
import com.uid2.core.service.AttestationService;
import com.uid2.shared.Const;
import com.uid2.shared.attest.IAttestationTokenService;
import com.uid2.shared.auth.IAuthorizableProvider;
import com.uid2.shared.auth.IEnclaveIdentifierProvider;
import com.uid2.shared.auth.OperatorKey;
import com.uid2.shared.auth.Role;
import com.uid2.shared.cloud.CloudStorageException;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.secure.AttestationException;
import com.uid2.shared.secure.AttestationFailure;
import com.uid2.shared.secure.AttestationResult;
import com.uid2.shared.secure.IAttestationProvider;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
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

import javax.crypto.Cipher;
import java.io.*;
import java.net.URL;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.Callable;

import static com.uid2.shared.Utils.readToEndAsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * UID2-576 Make sure that private operator only gets site-specific client keys/keys/keys_acl data
 * while public operators will get the unfiltered global data set
 */
@ExtendWith(VertxExtension.class)
public class TestSiteSpecificMetadataPath {

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

  private AttestationService attestationService;

  private static final String attestationProtocol = "test-attestation-protocol";

  @BeforeEach
  void deployVerticle(Vertx vertx, VertxTestContext testContext) throws Throwable {
    attestationService = new AttestationService();
    SecretStore.Global.load(((JsonObject) Json.decodeValue(openFile("/com.uid2.core/testSiteSpecificMetadata/test-config.json"))));
    MockitoAnnotations.initMocks(this);
    CoreVerticle verticle = new CoreVerticle(cloudStorage, authProvider, attestationService, attestationTokenService, enclaveIdentifierProvider);
    vertx.deployVerticle(verticle, testContext.succeeding(id -> testContext.completeNow()));
  }

  private String getUrlForEndpoint(String endpoint) {
    return String.format("http://127.0.0.1:%d/%s", Const.Port.ServicePortForCore, endpoint);
  }

  private void fakeAuth(boolean isPublicOperator, int siteId) {
    OperatorKey clientKey = new OperatorKey("test-key", "", "", attestationProtocol, 0, false, siteId, isPublicOperator);
    when(authProvider.get(any())).thenReturn(clientKey);
  }

  private void get(Vertx vertx, String endpoint, String body, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
    WebClient client = WebClient.create(vertx);
    client.getAbs(getUrlForEndpoint(endpoint)).sendBuffer(Buffer.buffer(body), handler);
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
  void publicOperatorGetsGlobalKeys(Vertx vertx, VertxTestContext testContext) throws CloudStorageException, IOException {
    genericSiteSpecificTest(vertx, testContext, true, 99, "keys", "keys","key/refresh");
  }

  @Test
  void privateOperatorGetsSiteSpecificKeys(Vertx vertx, VertxTestContext testContext) throws CloudStorageException, IOException
  {
    genericSiteSpecificTest(vertx, testContext, false, 108, "keys", "keys","key/refresh");
  }

  @Test
  void publicOperatorGetsGlobalClientKeys(Vertx vertx, VertxTestContext testContext) throws CloudStorageException, IOException {
    genericSiteSpecificTest(vertx, testContext, true, 99, "clients", "client_keys","clients/refresh");
  }

  @Test
  void privateOperatorGetsSiteSpecificClientKeys(Vertx vertx, VertxTestContext testContext) throws CloudStorageException, IOException
  {
    genericSiteSpecificTest(vertx, testContext, false, 108, "clients", "client_keys", "clients/refresh");
  }

  @Test
  void publicOperatorGetsGlobalKeysACL(Vertx vertx, VertxTestContext testContext) throws CloudStorageException, IOException {
    genericSiteSpecificTest(vertx, testContext, true, 99, "keys_acl", "keys_acl","/key/acl/refresh");
  }

  @Test
  void privateOperatorGetsSiteSpecificKeysACL(Vertx vertx, VertxTestContext testContext) throws CloudStorageException, IOException
  {
    genericSiteSpecificTest(vertx, testContext, false, 108, "keys_acl", "keys_acl", "/key/acl/refresh");
  }

  void genericSiteSpecificTest(Vertx vertx, VertxTestContext testContext, boolean isPublicOperator, int siteId, String dataType, String jsonObjectContainingLocation, String endPoint) throws CloudStorageException, IOException
  {
    String privateSiteMetaDataURL = "sites/"+ siteId+ "/com.uid2.core/testSiteSpecificMetadata/"+dataType+"/metadata.json";
    String publicSiteMetaData =  "/com.uid2.core/testSiteSpecificMetadata/"+dataType+"/metadata.json";

    String privateMetaDataContent = openFile("/com.uid2.core/testSiteSpecificMetadata/"+dataType+"/sites/"+ siteId+ "/metadata.json");
    String publicMetaDataContent = openFile(publicSiteMetaData);

    String finalPrivateDataLocation = ((JsonObject) Json.decodeValue(privateMetaDataContent)).getJsonObject(jsonObjectContainingLocation).getString("location");
    String finalPublicDataLocation = ((JsonObject) Json.decodeValue(publicMetaDataContent)).getJsonObject(jsonObjectContainingLocation).getString("location");

    when(cloudStorage.download(eq(privateSiteMetaDataURL))).thenReturn(new StringBufferInputStream(privateMetaDataContent));
    when(cloudStorage.download(eq(publicSiteMetaData))).thenReturn(new StringBufferInputStream(publicMetaDataContent));
    when(cloudStorage.preSignUrl(any())).thenAnswer(i -> new URL(i.getArgument(0)));

    fakeAuth(isPublicOperator, siteId);
    setupAttestation();
    get(vertx, endPoint, makeAttestationRequestJson("xxx", "yyy"), ar -> {
      assertTrue(ar.succeeded());
      HttpResponse response = ar.result();
      assertEquals(200, response.statusCode());
      JsonObject json = response.bodyAsJsonObject();
      String resultLocation = json.getJsonObject(jsonObjectContainingLocation).getString("location");
      assertEquals(resultLocation, isPublicOperator?finalPublicDataLocation:finalPrivateDataLocation);
      testContext.completeNow();
    });
  }


  void setupAttestation()
  {
    addAttestationProvider(attestationProtocol);
    onHandleAttestationRequest(() -> {
      byte[] resultPublicKey = null;
      return Future.succeededFuture(new AttestationResult(resultPublicKey));
    });
    when(attestationTokenService.createToken(any(), any(), any(), any())).thenReturn("test-attestion-token");
  }

  String openFile(String filePath) throws IOException
  {
    return readToEndAsString(TestSiteSpecificMetadataPath.class.getResourceAsStream(filePath));
  }


}