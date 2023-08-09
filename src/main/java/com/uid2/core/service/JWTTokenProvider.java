package com.uid2.core.service;

import com.uid2.core.model.ConfigStore;
import com.uid2.shared.Const;
import com.uid2.shared.cloud.CloudUtils;
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
import software.amazon.awssdk.auth.credentials.InstanceProfileCredentialsProvider;
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
        return new StringBuilder()
                .append(jwtContent)
                .append(".")
                .append(signature)
                .toString();
    }

    private String signJwtContent(KmsClient kmsClient, String jwtContents) throws JwtSigningException {
        try {
            String keyId = ConfigStore.Global.get(AwsKmsJwtSigningKeyIdProp);
            if (keyId == null || keyId.isEmpty()) {
                String message = "Unable to retrieve the AWS KMS Key Id from config. Unable to sign JWT token";
                LOGGER.error(message);
                throw new JwtSigningException(Optional.of(message));
            }

            SdkBytes dataToSign = SdkBytes.fromUtf8String(jwtContents);

            SignRequest request = SignRequest.builder()
                    .keyId(keyId)
                    .signingAlgorithm(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256)
                    .message(dataToSign)
                    .build();

            SignResponse response = kmsClient.sign(request);
            if (response.sdkHttpResponse().isSuccessful()) {
                String signature = encoder.encodeToString(response.signature().asByteArray());
                return signature;
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

        String accessKeyId = config.getString(Const.Config.AccessKeyIdProp);
        String secretAccessKey = config.getString(Const.Config.SecretAccessKeyProp);
        String s3Endpoint = config.getString(Const.Config.S3EndpointProp);
        String awsRegion = config.getString(Const.Config.AwsRegionProp);

        if (accessKeyId != null && !accessKeyId.isEmpty() && secretAccessKey != null && !secretAccessKey.isEmpty()) {
            AwsBasicCredentials basicCredentials = AwsBasicCredentials.create(accessKeyId, secretAccessKey);

            StaticCredentialsProvider.create(basicCredentials);
            try {
                client = kmsClientBuilder
                        .endpointOverride(new URI(s3Endpoint))
                        .region(Region.of(awsRegion))
                        .credentialsProvider(StaticCredentialsProvider.create(basicCredentials))
                        .build();
            } catch (URISyntaxException e) {
                LOGGER.error("Error creating KMS Client Builder using static credentials.", e);
                throw e;
            }
        } else {
            InstanceProfileCredentialsProvider credentialsProvider = InstanceProfileCredentialsProvider.create();

            client = kmsClientBuilder
                    .region(Region.of(awsRegion))
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
