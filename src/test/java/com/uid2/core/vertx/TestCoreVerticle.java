// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package com.uid2.core.vertx;

import com.uid2.core.service.AttestationService;
import com.uid2.shared.Const;
import com.uid2.shared.attest.IAttestationTokenService;
import com.uid2.shared.auth.*;
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
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.Callable;

import static org.mockito.Mockito.*;

@ExtendWith(VertxExtension.class)
public class TestCoreVerticle {
  @Mock
  private ICloudStorage cloudStorage;
  @Mock
  private IAuthProvider authProvider;
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
    MockitoAnnotations.initMocks(this);
    CoreVerticle verticle = new CoreVerticle(cloudStorage, authProvider, attestationService, attestationTokenService, enclaveIdentifierProvider);
    vertx.deployVerticle(verticle, testContext.succeeding(id -> testContext.completeNow()));
  }

  private String getUrlForEndpoint(String endpoint) {
    return String.format("http://127.0.0.1:%d/%s", Const.Port.ServicePortForCore, endpoint);
  }

  private void fakeAuth(Role role) {
    OperatorKey clientKey = new OperatorKey("test-key", "", "", attestationProtocol, 0, false);
    when(authProvider.get(any())).thenReturn(clientKey);
  }

  private void post(Vertx vertx, String endpoint, String body, Handler<AsyncResult<HttpResponse<Buffer>>> handler) {
    WebClient client = WebClient.create(vertx);
    client.postAbs(getUrlForEndpoint(endpoint)).sendBuffer(Buffer.buffer(body), handler);
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
      return Future.succeededFuture(new AttestationResult(resultPublicKey));
    });
    when(attestationTokenService.createToken(any(), any(), any(), any())).thenReturn("test-attestion-token");
    post(vertx, "attest", makeAttestationRequestJson("xxx", "yyy"), ar -> {
      assertTrue(ar.succeeded());
      HttpResponse response = ar.result();
      assertEquals(200, response.statusCode());
      JsonObject json = response.bodyAsJsonObject();
      String attestationToken = json.getJsonObject("body").getString("attestation_token");
      assertEquals("test-attestion-token", attestationToken);
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
      return Future.succeededFuture(new AttestationResult(publicKey));
    });
    when(attestationTokenService.createToken(any(), any(), any(), any())).thenReturn("test-attestion-token");
    post(vertx, "attest", makeAttestationRequestJson("xxx", "yyy"), ar -> {
      assertTrue(ar.succeeded());
      HttpResponse response = ar.result();
      assertEquals(200, response.statusCode());
      JsonObject json = response.bodyAsJsonObject();
      String attestationToken = json.getJsonObject("body").getString("attestation_token");
      assertNotEquals("", attestationToken);

      String[] decryptedAttestationToken = {""};
      assertDoesNotThrow(() -> {
        Cipher cipher = Cipher.getInstance(Const.Name.AsymetricEncryptionCipherClass);
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        decryptedAttestationToken[0] = new String(cipher.doFinal(Base64.getDecoder().decode(attestationToken)));
      });

      assertEquals("test-attestion-token", decryptedAttestationToken[0]);

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
      return Future.succeededFuture(new AttestationResult(publicKey));
    });
    when(attestationTokenService.createToken(any(), any(), any(), any())).thenReturn("test-attestion-token");
    post(vertx, "attest", makeAttestationRequestJson("xxx", null), ar -> {
      assertTrue(ar.succeeded());
      HttpResponse response = ar.result();
      assertEquals(200, response.statusCode());
      JsonObject json = response.bodyAsJsonObject();
      String attestationToken = json.getJsonObject("body").getString("attestation_token");
      assertNotEquals("", attestationToken);

      String[] decryptedAttestationToken = {""};
      assertDoesNotThrow(() -> {
        Cipher cipher = Cipher.getInstance(Const.Name.AsymetricEncryptionCipherClass);
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        decryptedAttestationToken[0] = new String(cipher.doFinal(Base64.getDecoder().decode(attestationToken)));
      });

      assertEquals("test-attestion-token", decryptedAttestationToken[0]);

      testContext.completeNow();
    });
  }
}
