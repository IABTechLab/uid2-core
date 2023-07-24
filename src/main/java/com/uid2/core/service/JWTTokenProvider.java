package com.uid2.core.service;

import com.uid2.core.model.ConfigStore;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
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
import software.amazon.awssdk.services.kms.endpoints.KmsEndpointProvider;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import static com.uid2.shared.Const.Config.*;

public class JWTTokenProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(JWTTokenProvider.class);
    private static final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

    private final KmsClientBuilder kmsClientBuilder;

    public JWTTokenProvider(KmsClientBuilder clientBuilder) {
        this.kmsClientBuilder = clientBuilder;
    }

    public String getJWT(Map<String, String> customClaims) throws JwtSigningException {
        return this.getJWT(null, customClaims);
    }

    public String getJWT(Map<String, String> headers, Map<String, String> customClaims) throws JwtSigningException {
        // headers we are going to use are:
        // "typ: : "JWT",
        // "alg" : "RS256"

        JsonObject headersJson = new JsonObject();
        headersJson.put("typ", "JWT");
        headersJson.put("alg", "RS256");
        if (headers != null && !headers.entrySet().isEmpty()) {
            for (Map.Entry<String, String> headerEntry : headers.entrySet()) {
                headersJson.put(headerEntry.getKey(), headerEntry.getValue());
            }
        }

        JsonObject claimsJson = new JsonObject();
        for (Map.Entry<String, String> claim : customClaims.entrySet()) {
            claimsJson.put(claim.getKey(), claim.getValue());
        }

        String jwtContent = new StringBuilder()
                .append(encoder.encodeToString(headersJson.encode().getBytes(StandardCharsets.UTF_8)))
                .append(".")
                .append(encoder.encodeToString(claimsJson.encode().getBytes(StandardCharsets.UTF_8)))
                .toString();

        KmsClient client = getKmsClient();
        String signature = signJwtContent(client, jwtContent);
        return new StringBuilder()
                .append(jwtContent)
                .append(".")
                .append(signature)
                .toString();
    }

    private KmsClient getKmsClient() {
        KmsClient client = null;
        String accessKeyId = ConfigStore.Global.get(AccessKeyIdProp);
        String secretAccessKey = ConfigStore.Global.get(SecretAccessKeyProp);
        String s3Endpoint = ConfigStore.Global.get(S3EndpointProp);

        if (accessKeyId != null && !accessKeyId.isEmpty() && secretAccessKey != null && !secretAccessKey.isEmpty()) {
            AwsBasicCredentials basicCredentials = AwsBasicCredentials.create(accessKeyId, secretAccessKey);

            software.amazon.awssdk.auth.credentials.StaticCredentialsProvider.create(basicCredentials);
            try {
                client = this.kmsClientBuilder
                        .endpointOverride(new URI(s3Endpoint))
                        .region(Region.of(ConfigStore.Global.get(AwsRegionProp)))
                        .credentialsProvider(StaticCredentialsProvider.create(basicCredentials))
                        .build();
            } catch (URISyntaxException e) {
                LOGGER.error("Error creating KMS Client Builder using static credentials.", e);
            }
        } else {
            InstanceProfileCredentialsProvider credentialsProvider = InstanceProfileCredentialsProvider.create();

            client = this.kmsClientBuilder
                    .region(Region.of(ConfigStore.Global.get(AwsRegionProp)))
                    .credentialsProvider(credentialsProvider)
                    .build();
        }

        return client;
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

    public class JwtSigningException extends Exception {
        public JwtSigningException(Optional<String> message) {
            super(message == null ? "No message returned from KMS Client" : message.orElse("No message returned from KMS Client"));
        }
    }

}
