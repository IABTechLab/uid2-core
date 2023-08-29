package com.uid2.core.vertx;

import com.uid2.core.model.ConfigStore;
import com.uid2.core.model.SecretStore;
import com.uid2.core.service.AttestationService;
import com.uid2.core.service.OperatorJWTTokenProvider;
import com.uid2.shared.Const;
import com.uid2.shared.attest.IAttestationTokenService;
import com.uid2.shared.attest.JwtService;
import com.uid2.shared.auth.*;
import com.uid2.shared.cloud.CloudStorageException;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.secure.IAttestationProvider;
import io.vertx.core.AsyncResult;
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
import java.io.*;
import java.net.URL;
import java.util.HashSet;

import static com.uid2.shared.Utils.readToEndAsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * UID2-576 Make sure that private operator only gets site-specific client keys/keys/keys_acl data
 * while public operators will get the unfiltered global data set.
 *
 * See TestSitesMetadataPath for testing public operator able to retrieve site metadata for CSTG use.
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
  @Mock
  private OperatorJWTTokenProvider operatorJWTTokenProvider;
  @Mock
  private JwtService jwtService;

  private AttestationService attestationService;

  // we need trusted to skip the attestation procedure or otherwise the core encpoint call made in this file will
  // fail at the attestation handler
  private static final String attestationProtocol = "trusted";

  @BeforeEach
  void deployVerticle(Vertx vertx, VertxTestContext testContext) throws Throwable {
    attestationService = new AttestationService();
    SecretStore.Global.load(((JsonObject) Json.decodeValue(openFile("/com.uid2.core/testSiteSpecificMetadata/test-secrets.json"))));
    ConfigStore.Global.load(((JsonObject) Json.decodeValue(openFile("/com.uid2.core/testSiteSpecificMetadata/test-configs-provide-private-site-data.json"))));
    MockitoAnnotations.initMocks(this);
    CoreVerticle verticle = new CoreVerticle(cloudStorage, authProvider, attestationService, attestationTokenService, enclaveIdentifierProvider, operatorJWTTokenProvider, jwtService);
    vertx.deployVerticle(verticle, testContext.succeeding(id -> testContext.completeNow()));
  }

  private String getUrlForEndpoint(String endpoint) {
    return String.format("http://127.0.0.1:%d/%s", Const.Port.ServicePortForCore, endpoint);
  }

  private void fakeAuth(OperatorType operatorType, int siteId) {
    OperatorKey clientKey = new OperatorKey("test-key", "", "", attestationProtocol, 0, false, siteId, new HashSet<>(), operatorType);
    when(authProvider.get(any())).thenReturn(clientKey);
  }

  private void get(Vertx vertx, String endpoint, String body, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
    WebClient client = WebClient.create(vertx);
    client.getAbs(getUrlForEndpoint(endpoint)).sendBuffer(Buffer.buffer(body), handler);
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
    genericSiteSpecificTest(vertx, testContext, OperatorType.PUBLIC, 99, "keys", "keys","key/refresh");
  }

  @Test
  void privateOperatorGetsSiteSpecificKeys(Vertx vertx, VertxTestContext testContext) throws CloudStorageException, IOException {
    genericSiteSpecificTest(vertx, testContext, OperatorType.PRIVATE, 108, "keys", "keys","key/refresh");
  }

  @Test
  void publicOperatorGetsGlobalClientKeys(Vertx vertx, VertxTestContext testContext) throws CloudStorageException, IOException {
    genericSiteSpecificTest(vertx, testContext, OperatorType.PUBLIC, 99, "clients", "client_keys","clients/refresh");
  }

  @Test
  void privateOperatorGetsSiteSpecificClientKeys(Vertx vertx, VertxTestContext testContext) throws CloudStorageException, IOException {
    genericSiteSpecificTest(vertx, testContext, OperatorType.PRIVATE, 108, "clients", "client_keys", "clients/refresh");
  }

  @Test
  void publicOperatorGetsGlobalKeysACL(Vertx vertx, VertxTestContext testContext) throws CloudStorageException, IOException {
    genericSiteSpecificTest(vertx, testContext, OperatorType.PUBLIC, 99, "keys_acl", "keys_acl","/key/acl/refresh");
  }

  @Test
  void privateOperatorGetsSiteSpecificKeysACL(Vertx vertx, VertxTestContext testContext) throws CloudStorageException, IOException {
    genericSiteSpecificTest(vertx, testContext, OperatorType.PRIVATE, 108, "keys_acl", "keys_acl", "/key/acl/refresh");
  }

  void genericSiteSpecificTest(Vertx vertx, VertxTestContext testContext, OperatorType operatorType, int siteId, String dataType, String jsonObjectContainingLocation, String endPoint) throws CloudStorageException, IOException {
    //example: /com.uid2.core/testSiteSpecificMetadata/keys/site/108/metadata.json
    String privateSiteMetaDataURL = "/com.uid2.core/testSiteSpecificMetadata/"+dataType+"/site/"+ siteId+ "/metadata.json";

    String publicSiteMetaData =  "/com.uid2.core/testSiteSpecificMetadata/"+dataType+"/metadata.json";

    String privateMetaDataContent = openFile("/com.uid2.core/testSiteSpecificMetadata/"+dataType+"/site/"+ siteId+ "/metadata.json");
    String publicMetaDataContent = openFile(publicSiteMetaData);

    String finalPrivateDataLocation = ((JsonObject) Json.decodeValue(privateMetaDataContent)).getJsonObject(jsonObjectContainingLocation).getString("location");
    String finalPublicDataLocation = ((JsonObject) Json.decodeValue(publicMetaDataContent)).getJsonObject(jsonObjectContainingLocation).getString("location");

    when(cloudStorage.download(eq(privateSiteMetaDataURL))).thenReturn(new StringBufferInputStream(privateMetaDataContent));
    when(cloudStorage.download(eq(publicSiteMetaData))).thenReturn(new StringBufferInputStream(publicMetaDataContent));
    when(cloudStorage.preSignUrl(any())).thenAnswer(i -> new URL(i.getArgument(0)));

    fakeAuth(operatorType, siteId);
    get(vertx, endPoint, "", ar -> {
      assertTrue(ar.succeeded());
      HttpResponse response = ar.result();
      assertEquals(200, response.statusCode());
      JsonObject json = response.bodyAsJsonObject();
      String resultLocation = json.getJsonObject(jsonObjectContainingLocation).getString("location");
      assertEquals(resultLocation, operatorType==OperatorType.PUBLIC?finalPublicDataLocation:finalPrivateDataLocation);
      testContext.completeNow();
    });
  }

  String openFile(String filePath) throws IOException
  {
    return readToEndAsString(TestSiteSpecificMetadataPath.class.getResourceAsStream(filePath));
  }

}
