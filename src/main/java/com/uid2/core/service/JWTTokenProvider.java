package com.uid2.core.service;

import com.uid2.core.model.ConfigStore;
import com.uid2.shared.Const;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.WebIdentityTokenFileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import static com.uid2.shared.Const.Config.*;
import static com.uid2.core.Const.Config.*;

public class JWTTokenProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(JWTTokenProvider.class);
    private static final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

    private final JsonObject config;
    private final KmsClientBuilder kmsClientBuilder;

    public JWTTokenProvider(JsonObject config, KmsClientBuilder clientBuilder) {
        this.config = config;
        this.kmsClientBuilder = clientBuilder;
    }

    public String getJWT(Instant expiresAt, Instant issuedAt, Map<String, String> customClaims) throws JwtSigningException {
        return this.getJWT(expiresAt, issuedAt, null, customClaims);
    }

    public String getJWT(Instant expiresAt, Instant issuedAt, Map<String, String> headers, Map<String, String> customClaims) throws JwtSigningException {
        JsonObject headersJson = new JsonObject();
        headersJson.put("typ", "JWT");
        headersJson.put("alg", "RS256");
        this.addMapToJsonObject(headersJson, headers);

        JsonObject claimsJson = new JsonObject();
        claimsJson.put("exp", expiresAt.getEpochSecond());
        claimsJson.put("iat", issuedAt.getEpochSecond());
        this.addMapToJsonObject(claimsJson, customClaims);

        String jwtContent = new StringBuilder()
                .append(encoder.encodeToString(headersJson.encode().getBytes(StandardCharsets.UTF_8)))
                .append(".")
                .append(encoder.encodeToString(claimsJson.encode().getBytes(StandardCharsets.UTF_8)))
                .toString();

        KmsClient client = null;
        try {
            client = getKmsClient(this.kmsClientBuilder, this.config);
        } catch (URISyntaxException e) {
            throw new JwtSigningException(Optional.of("Unable to get KMS Client"), e);
        }
        String signature = signJwtContent(client, jwtContent);
        if (signature != null && !signature.isBlank()) {
            return new StringBuilder()
                    .append(jwtContent)
                    .append(".")
                    .append(signature)
                    .toString();
        } else {
            return "";
        }
    }

    private String signJwtContent(KmsClient kmsClient, String jwtContents) throws JwtSigningException {
        try {
            String keyId = ConfigStore.Global.get(AwsKmsJwtSigningKeyIdProp);
            Boolean enforceJWT = ConfigStore.Global.getBoolean(EnforceJwtProp);
            if (enforceJWT == null) {
                enforceJWT = false;
            }

            if (keyId == null || keyId.isEmpty()) {
                if (enforceJWT) {
                    String message = "Unable to retrieve the AWS KMS Key Id from config. Unable to sign JWT token";
                    LOGGER.error(message);
                    throw new JwtSigningException(Optional.of(message));
                } else {
                    return "";
                }
            }

            SdkBytes dataToSign = SdkBytes.fromUtf8String(jwtContents);

            SignRequest request = SignRequest.builder()
                    .keyId(keyId)
                    .signingAlgorithm(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256)
                    .message(dataToSign)
                    .build();

            SignResponse response = kmsClient.sign(request);
            if (response.sdkHttpResponse().isSuccessful()) {
                return encoder.encodeToString(response.signature().asByteArray());
            } else {
                LOGGER.error("Error returned when attempting to sign JWT: {}", response.sdkHttpResponse().statusText());
                throw new JwtSigningException(response.sdkHttpResponse().statusText());
            }
        } catch (KmsException e) {
            String message = "Error signing JWT Token.";
            LOGGER.error(message, e);
            throw new JwtSigningException(Optional.of(message));
        }
    }

    private void addMapToJsonObject(JsonObject jsonObject, Map<String, String> map) {
        if (map != null) {
            for (Map.Entry<String, String> entry : map.entrySet()) {
                jsonObject.put(entry.getKey(), entry.getValue());
            }
        }
    }

    private static KmsClient getKmsClient(KmsClientBuilder kmsClientBuilder, JsonObject config) throws URISyntaxException {
        KmsClient client;

        String region = config.getString(KmsRegionProp, config.getString(Const.Config.AwsRegionProp));
        String accessKeyId = config.getString(KmsAccessKeyIdProp);
        String secretAccessKey = config.getString(KmsSecretAccessKeyProp);
        String endpoint = config.getString(KmsEndpointProp);

        if (accessKeyId != null && !accessKeyId.isBlank() && secretAccessKey != null && !secretAccessKey.isBlank()) {
            AwsBasicCredentials basicCredentials = AwsBasicCredentials.create(accessKeyId, secretAccessKey);

            StaticCredentialsProvider.create(basicCredentials);
            try {
                if (endpoint != null && !endpoint.isBlank()) {
                    kmsClientBuilder.endpointOverride(new URI(endpoint));
                }

                client = kmsClientBuilder
                        .region(Region.of(region))
                        .credentialsProvider(StaticCredentialsProvider.create(basicCredentials))
                        .build();
            } catch (URISyntaxException e) {
                LOGGER.error("Error creating KMS Client Builder using static credentials.", e);
                throw e;
            }
        } else {
            WebIdentityTokenFileCredentialsProvider credentialsProvider = WebIdentityTokenFileCredentialsProvider.create();

            client = kmsClientBuilder
                    .region(Region.of(region))
                    .credentialsProvider(credentialsProvider)
                    .build();
        }

        return client;
    }

    public class JwtSigningException extends Exception {
        public JwtSigningException(Optional<String> message) {
            this(message, null);
        }

        public JwtSigningException(Optional<String> message, Exception e) {
            super(message == null ? "No message returned from KMS Client" : message.orElse("No message returned from KMS Client"), e);
        }
    }
}
