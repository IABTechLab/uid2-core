package com.uid2.core.service;

import com.uid2.core.model.ConfigStore;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Optional;

import static com.uid2.shared.Utils.readToEndAsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JWTTokenProviderTest {
    private final JsonObject defaultHeaders = new JsonObject();

    private KmsClient mockClient;
    private ArgumentCaptor<SignRequest> capturedSignRequest;
    private JsonObject config;

    @BeforeEach
    void setUp() throws IOException {
        this.config = ((JsonObject) Json.decodeValue(openFile("/com.uid2.core/service/jwt-token-provider-test-config.json")));
        ConfigStore.Global.load(config);
        defaultHeaders.put("typ", "JWT");
        defaultHeaders.put("alg", "RS256");
    }

    @Test
    void getJwtReturnsValidToken() throws JWTTokenProvider.JwtSigningException {

        HashMap<String, String> headers = new HashMap<>();
        headers.put("a", "b");
        headers.put("c", "d");

        HashMap<String, String> content = new HashMap<>();
        content.put("sub", "subject");
        content.put("iss", "issuer");

        var builder = getBuilder(true, "TestSignature");
        JWTTokenProvider provider = new JWTTokenProvider(config, builder);

        Instant i = Clock.systemUTC().instant();

        String result = provider.getJWT(i, i, headers, content);

        String expectedSig = "TestSignature";

        assertNotNull(result);
        defaultHeaders.put("a", "b");
        defaultHeaders.put("c", "d");

        JsonObject contentJson = new JsonObject();
        contentJson.put("exp", i.getEpochSecond());
        contentJson.put("iat", i.getEpochSecond());
        contentJson.put("sub", "subject");
        contentJson.put("iss", "issuer");

        assertJWT(defaultHeaders.encode(), contentJson.encode(), expectedSig, result);
        assertEquals("1234", this.capturedSignRequest.getValue().keyId());
        assertEquals(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256, this.capturedSignRequest.getValue().signingAlgorithm());
    }

    @Test
    void getJwtEmptySignatureThrowsException() {
        var builder = getBuilder(false, "");

        JWTTokenProvider provider = new JWTTokenProvider(config, builder);

        JWTTokenProvider.JwtSigningException e = assertThrows(
                JWTTokenProvider.JwtSigningException.class,
                () -> provider.getJWT(Clock.systemUTC().instant().plusSeconds(600), Clock.systemUTC().instant(), new HashMap<>(), new HashMap<>()));

        assertEquals("Test status text", e.getMessage());
    }

    @Test
    void getJwtEmptySignatureEmptyResponseText() {
        var builder = getBuilder(false, "", Optional.empty());

        JWTTokenProvider provider = new JWTTokenProvider(config, builder);

        JWTTokenProvider.JwtSigningException e = assertThrows(
                JWTTokenProvider.JwtSigningException.class,
                () -> provider.getJWT(Clock.systemUTC().instant().plusSeconds(600), Clock.systemUTC().instant(), new HashMap<>(), new HashMap<>()));

        assertEquals("No message returned from KMS Client", e.getMessage());
    }

    @Test
    void getJwtEmptySignatureNullResponseText() {
        var builder = getBuilder(false, "", null);

        JWTTokenProvider provider = new JWTTokenProvider(config, builder);

        JWTTokenProvider.JwtSigningException e = assertThrows(
                JWTTokenProvider.JwtSigningException.class,
                () -> provider.getJWT(Clock.systemUTC().instant().plusSeconds(600), Clock.systemUTC().instant(), new HashMap<>(), new HashMap<>()));

        assertEquals("No message returned from KMS Client", e.getMessage());
    }

    @Test
    void getJwtSignatureThrowsKmsException() {
        var builder = getBuilder(false, "", Optional.empty());

        JWTTokenProvider provider = new JWTTokenProvider(config, builder);
        var ex = KmsException.builder().message("Test Error").build();
        when(mockClient.sign(capturedSignRequest.capture())).thenThrow(ex);

        JWTTokenProvider.JwtSigningException e = assertThrows(
                JWTTokenProvider.JwtSigningException.class,
                () -> provider.getJWT(Clock.systemUTC().instant().plusSeconds(600), Clock.systemUTC().instant(), new HashMap<>(), new HashMap<>()));

        assertEquals("Error signing JWT Token.", e.getMessage());
    }

    @Test
    void getJwtMissingKeyInConfig() throws IOException {
        var data = (JsonObject) Json.decodeValue(openFile("/com.uid2.core/service/jwt-token-provider-test-config.json"));
        data.put("aws_kms_jwt_signing_key_id", "");
        data.put("enforceJwt", true);

        ConfigStore.Global.load(data);

        var builder = getBuilder(false, "", Optional.empty());

        JWTTokenProvider provider = new JWTTokenProvider(config, builder);

        JWTTokenProvider.JwtSigningException e = assertThrows(
                JWTTokenProvider.JwtSigningException.class,
                () -> provider.getJWT(Clock.systemUTC().instant().plusSeconds(600), Clock.systemUTC().instant(), new HashMap<>(), new HashMap<>()));

        assertEquals("Unable to retrieve the AWS KMS Key Id from config. Unable to sign JWT token", e.getMessage());
    }

    String openFile(String filePath) throws IOException {
        return readToEndAsString(JWTTokenProviderTest.class.getResourceAsStream(filePath));
    }

    private KmsClientBuilder getBuilder(boolean isSuccessful, String signature) {
        return getBuilder(isSuccessful, signature, Optional.of("Test status text"));
    }

    private KmsClientBuilder getBuilder(boolean isSuccessful, String signature, Optional<String> statusText) {
        SdkHttpResponse sdkHttpResponse = mock(SdkHttpResponse.class);
        when(sdkHttpResponse.isSuccessful()).thenReturn(isSuccessful);
        when(sdkHttpResponse.statusText()).thenReturn(statusText);

        SignResponse response = mock(SignResponse.class);
        when(response.sdkHttpResponse()).thenReturn(sdkHttpResponse);
        when(response.signature()).thenReturn(SdkBytes.fromUtf8String(signature));

        mockClient = mock(KmsClient.class);
        capturedSignRequest = ArgumentCaptor.forClass(SignRequest.class);
        when(mockClient.sign(capturedSignRequest.capture())).thenReturn(response);

        KmsClientBuilder builder = mock(KmsClientBuilder.class);
        when(builder.region(any(Region.class))).thenReturn(builder);
        when(builder.credentialsProvider(any(AwsCredentialsProvider.class))).thenReturn(builder);
        when(builder.build()).thenReturn(mockClient);

        return builder;
    }

    private void assertJWT(String expectedHeader, String expectedContent, String expectedSignature, String jwt) {
        var decoder = Base64.getUrlDecoder();
        var parts = jwt.split("\\.");
        String header = new String(decoder.decode(parts[0]));
        assertEquals(expectedHeader, header);

        String content = new String(decoder.decode(parts[1]));
        assertEquals(expectedContent, content);

        assertEquals(expectedSignature, new String(decoder.decode(parts[2])));
    }
}
