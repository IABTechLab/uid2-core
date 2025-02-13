package com.uid2.core.vertx;

import com.uid2.core.handler.AttestationFailureHandler;
import com.uid2.core.handler.ExceptionFilterBodyHandler;
import com.uid2.core.handler.GenericFailureHandler;
import com.uid2.core.model.ConfigStore;
import com.uid2.core.service.*;
import com.uid2.core.util.OperatorInfo;
import com.uid2.shared.Const;

import com.uid2.shared.Utils;
import com.uid2.shared.attest.EncryptedAttestationToken;
import com.uid2.shared.attest.IAttestationTokenService;
import com.uid2.shared.attest.JwtService;
import com.uid2.shared.auth.*;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.health.HealthComponent;
import com.uid2.shared.health.HealthManager;
import com.uid2.shared.middleware.AttestationMiddleware;
import com.uid2.shared.middleware.AuthMiddleware;
import com.uid2.shared.secure.*;
import com.uid2.shared.vertx.RequestCapturingHandler;
import com.uid2.shared.vertx.VertxUtils;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.file.FileSystem;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.CorsHandler;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Callable;

import com.uid2.shared.store.reader.RotatingCloudEncryptionKeyProvider;
import com.uid2.shared.model.CloudEncryptionKey;

import static com.uid2.shared.Const.Config.EnforceJwtProp;

public class CoreVerticle extends AbstractVerticle {
    private final static Logger logger = LoggerFactory.getLogger(CoreVerticle.class);

    private final HealthComponent healthComponent = HealthManager.instance.registerComponent("http-server");
    private final AuthMiddleware auth;
    private final AttestationService attestationService;
    private final AttestationMiddleware attestationMiddleware;
    private final IAuthorizableProvider authProvider;
    private final IEnclaveIdentifierProvider enclaveIdentifierProvider;

    private final IAttestationTokenService attestationTokenService;
    private final SiteMetadataProvider siteMetadataProvider;
    private final ClientMetadataProvider clientMetadataProvider;
    private final ClientSideKeypairMetadataProvider clientSideKeypairMetadataProvider;
    private final ServiceMetadataProvider serviceMetadataProvider;
    private final ServiceLinkMetadataProvider serviceLinkMetadataProvider;
    private final OperatorMetadataProvider operatorMetadataProvider;
    private final KeyMetadataProvider keyMetadataProvider;
    private final KeyAclMetadataProvider keyAclMetadataProvider;
    private final KeysetMetadataProvider keysetMetadataProvider;
    private final KeysetKeyMetadataProvider keysetKeyMetadataProvider;
    private final SaltMetadataProvider saltMetadataProvider;
    private final PartnerMetadataProvider partnerMetadataProvider;
    private final OperatorJWTTokenProvider operatorJWTTokenProvider;
    private final RotatingCloudEncryptionKeyProvider cloudEncryptionKeyProvider;

    private final FileSystem fileSystem;

    public CoreVerticle(ICloudStorage cloudStorage,
                        IAuthorizableProvider authProvider,
                        AttestationService attestationService,
                        IAttestationTokenService attestationTokenService,
                        IEnclaveIdentifierProvider enclaveIdentifierProvider,
                        OperatorJWTTokenProvider operatorJWTTokenProvider,
                        JwtService jwtService,
                        RotatingCloudEncryptionKeyProvider cloudEncryptionKeyProvider,
                        FileSystem fileSystem) throws Exception {
        this.operatorJWTTokenProvider = operatorJWTTokenProvider;
        this.healthComponent.setHealthStatus(false, "not started");

        this.authProvider = authProvider;

        this.attestationService = attestationService;
        this.attestationTokenService = attestationTokenService;
        this.enclaveIdentifierProvider = enclaveIdentifierProvider;
        this.enclaveIdentifierProvider.addListener(this.attestationService);
        this.cloudEncryptionKeyProvider = cloudEncryptionKeyProvider;

        this.fileSystem = fileSystem;

        final String jwtAudience = ConfigStore.Global.get(Const.Config.CorePublicUrlProp);
        final String jwtIssuer = ConfigStore.Global.get(Const.Config.CorePublicUrlProp);
        Boolean enforceJwt = ConfigStore.Global.getBoolean(Const.Config.EnforceJwtProp);
        if (enforceJwt == null) {
            enforceJwt = false;
        }

        this.attestationMiddleware = new AttestationMiddleware(this.attestationTokenService, jwtService, jwtAudience, jwtIssuer, enforceJwt);

        this.auth = new AuthMiddleware(authProvider);

        this.siteMetadataProvider = new SiteMetadataProvider(cloudStorage);
        this.clientMetadataProvider = new ClientMetadataProvider(cloudStorage);
        this.operatorMetadataProvider = new OperatorMetadataProvider(cloudStorage);
        this.keyMetadataProvider = new KeyMetadataProvider(cloudStorage);
        this.keyAclMetadataProvider = new KeyAclMetadataProvider(cloudStorage);
        this.saltMetadataProvider = new SaltMetadataProvider(cloudStorage);
        this.partnerMetadataProvider = new PartnerMetadataProvider(cloudStorage);
        this.keysetMetadataProvider = new KeysetMetadataProvider(cloudStorage);
        this.keysetKeyMetadataProvider = new KeysetKeyMetadataProvider(cloudStorage);
        this.clientSideKeypairMetadataProvider = new ClientSideKeypairMetadataProvider(cloudStorage);
        this.serviceMetadataProvider = new ServiceMetadataProvider(cloudStorage);
        this.serviceLinkMetadataProvider = new ServiceLinkMetadataProvider(cloudStorage);
    }

    public CoreVerticle(ICloudStorage cloudStorage,
                        IAuthorizableProvider authorizableProvider,
                        AttestationService attestationService,
                        IAttestationTokenService attestationTokenService,
                        IEnclaveIdentifierProvider enclaveIdentifierProvider,
                        OperatorJWTTokenProvider jwtTokenProvider,
                        JwtService jwtService,
                        FileSystem fileSystem) throws Exception {
        this(cloudStorage, authorizableProvider, attestationService, attestationTokenService, enclaveIdentifierProvider, jwtTokenProvider, jwtService, null, fileSystem);
    }

    @Override
    public void start(Promise<Void> startPromise) {
        this.healthComponent.setHealthStatus(false, "still starting");

        final Router router = createRoutesSetup();

        final int portOffset = Utils.getPortOffset();
        final int port = Const.Port.ServicePortForCore + portOffset;
        vertx.createHttpServer()
                .requestHandler(router)
                .listen(port, result -> {
                    if (result.succeeded()) {
                        this.healthComponent.setHealthStatus(true);
                        startPromise.complete();
                    } else {
                        this.healthComponent.setHealthStatus(false, result.cause().getMessage());
                        startPromise.fail(result.cause());
                    }

                    logger.info("CoreVerticle instance started on HTTP port: {}", port);
                });
    }

    private Router createRoutesSetup() {
        final Router router = Router.router(vertx);

        router.route().handler(new ExceptionFilterBodyHandler());
        router.route().handler(new RequestCapturingHandler());
        router.route().handler(CorsHandler.create()
                .addRelativeOrigin(".*.")
                .allowedMethod(HttpMethod.GET)
                .allowedMethod(HttpMethod.POST)
                .allowedMethod(HttpMethod.OPTIONS)
                .allowedHeader("Access-Control-Request-Method")
                .allowedHeader("Access-Control-Allow-Credentials")
                .allowedHeader("Access-Control-Allow-Origin")
                .allowedHeader("Access-Control-Allow-Headers")
                .allowedHeader("Content-Type"));
        router.route().failureHandler(new GenericFailureHandler());

        router.post(Endpoints.ATTEST.toString())
                .handler(new AttestationFailureHandler())
                .handler(auth.handle(this::handleAttestAsync, Role.OPERATOR, Role.OPTOUT_SERVICE));
        router.get(Endpoints.CLOUD_ENCRYPTION_KEYS_RETRIEVE.toString()).handler(auth.handle(attestationMiddleware.handle(this::handleCloudEncryptionKeysRetrieval), Role.OPERATOR));
        router.get(Endpoints.SITES_REFRESH.toString()).handler(auth.handle(attestationMiddleware.handle(this::handleSiteRefresh), Role.OPERATOR));
        router.get(Endpoints.KEY_REFRESH.toString()).handler(auth.handle(attestationMiddleware.handle(this::handleKeyRefresh), Role.OPERATOR));
        router.get(Endpoints.KEY_ACL_REFRESH.toString()).handler(auth.handle(attestationMiddleware.handle(this::handleKeyAclRefresh), Role.OPERATOR));
        router.get(Endpoints.KEY_KEYSET_REFRESH.toString()).handler(auth.handle(attestationMiddleware.handle(this::handleKeysetRefresh), Role.OPERATOR));
        router.get(Endpoints.KEY_KEYSET_KEYS_REFRESH.toString()).handler(auth.handle(attestationMiddleware.handle(this::handleKeysetKeyRefresh), Role.OPERATOR));
        router.get(Endpoints.SALT_REFRESH.toString()).handler(auth.handle(attestationMiddleware.handle(this::handleSaltRefresh), Role.OPERATOR));
        router.get(Endpoints.CLIENTS_REFRESH.toString()).handler(auth.handle(attestationMiddleware.handle(this::handleClientRefresh), Role.OPERATOR));
        router.get(Endpoints.CLIENT_SIDE_KEYPAIRS_REFRESH.toString()).handler(auth.handle(attestationMiddleware.handle(this::handleClientSideKeypairRefresh), Role.OPERATOR));
        router.get(Endpoints.SERVICES_REFRESH.toString()).handler(auth.handle(attestationMiddleware.handle(this::handleServiceRefresh), Role.OPERATOR));
        router.get(Endpoints.SERVICE_LINKS_REFRESH.toString()).handler(auth.handle(attestationMiddleware.handle(this::handleServiceLinkRefresh), Role.OPERATOR));
        router.get(Endpoints.OPERATORS_REFRESH.toString()).handler(auth.handle(attestationMiddleware.handle(this::handleOperatorRefresh), Role.OPTOUT_SERVICE));
        router.get(Endpoints.PARTNERS_REFRESH.toString()).handler(auth.handle(attestationMiddleware.handle(this::handlePartnerRefresh), Role.OPTOUT_SERVICE));
        router.get(Endpoints.OPS_HEALTHCHECK.toString()).handler(this::handleHealthCheck);
        router.get(Endpoints.OPERATOR_CONFIG.toString()).handler(auth.handle(this::handleGetConfig, Role.OPERATOR));

        if (Optional.ofNullable(ConfigStore.Global.getBoolean("enable_test_endpoints")).orElse(false)) {
            router.route(Endpoints.ATTEST_GET_TOKEN.toString()).handler(auth.handle(this::handleTestGetAttestationToken, Role.OPERATOR));
        }

        return router;
    }

    private void handleGetConfig(RoutingContext rc) {
        fileSystem.readFile(com.uid2.core.Const.OPERATOR_CONFIG_PATH, ar -> {
            if (ar.succeeded()) {
                try {
                    String fileContent = ar.result().toString();
                    JsonObject configJson = new JsonObject(fileContent);
                    rc.response()
                            .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                            .end(configJson.encodePrettily());
                } catch (Exception e) {
                    rc.response()
                            .setStatusCode(500)
                            .end("Failed to parse configuration: " + e.getMessage());
                    throw new RuntimeException(e);
                }
            } else {
                rc.response()
                        .setStatusCode(500)
                        .end("Failed to retrieve configuration: " + ar.cause().getMessage());
            }
        });
    }


    private void handleHealthCheck(RoutingContext rc) {
        if (HealthManager.instance.isHealthy()) {
            rc.response().end("OK");
        } else {
            HttpServerResponse resp = rc.response();
            String reason = HealthManager.instance.reason();
            resp.setStatusCode(503);
            resp.setChunked(true);
            resp.write(reason);
            resp.end();
        }
    }

    private void handleAttestAsync(RoutingContext rc) {
        String token = AuthMiddleware.getAuthToken(rc);
        IAuthorizable profile = authProvider.get(token);

        OperatorKey operator = (OperatorKey) profile;
        String protocol = operator.getProtocol();

        JsonObject json;
        try {
            json = rc.body().asJsonObject();
        } catch (DecodeException e) {
            setAttestationFailureReason(rc, AttestationFailure.BAD_PAYLOAD, Collections.singletonMap("cause", AttestationFailure.BAD_PAYLOAD.explain()));
            Error("request body is not a valid json", 400, rc, null);
            return;
        }

        String request = json == null ? null : json.getString("attestation_request");

        if (request == null || request.isEmpty()) {
            setAttestationFailureReason(rc, AttestationFailure.BAD_PAYLOAD, Collections.singletonMap("cause", AttestationFailure.BAD_PAYLOAD.explain()));
            Error("no attestation_request attached", 400, rc, null);
            return;
        }

        String clientPublicKey = json.getString("public_key", "");

        try {
            attestationService.attest(protocol, request, clientPublicKey, ar -> {
                if (!ar.succeeded()) {
                    if (ar.cause() instanceof AttestationClientException ace && ace.IsClientError()) {
                        setAttestationFailureReason(rc, ace.getAttestationFailure(), Collections.singletonMap("reason", ace.getAttestationFailure().explain()));
                        logger.warn("attestation failure: ", ace);
                        Error("attestation failure", 400, rc, ace.getAttestationFailure().explain());
                        return;
                    }

                    // 500 is only for unknown errors in the attestation processing
                    setAttestationFailureReason(rc, AttestationFailure.INTERNAL_ERROR, Collections.singletonMap("cause", ar.cause().getMessage()));
                    logger.warn("attestation failure: ", ar.cause());
                    Error("attestation failure", 500, rc, null);
                    return;
                }

                final AttestationResult attestationResult = ar.result();
                if (!attestationResult.isSuccess()) {
                    AttestationFailure failure = attestationResult.getFailure();
                    switch (failure) {
                        case BAD_FORMAT:
                        case INVALID_PROTOCOL:
                        case BAD_CERTIFICATE:
                        case BAD_PAYLOAD:
                        case UNKNOWN_ATTESTATION_URL:
                        case FORBIDDEN_ENCLAVE:
                            setAttestationFailureReason(rc, failure, Collections.singletonMap("reason", attestationResult.getReason()));
                            Error(attestationResult.getReason(), 403, rc, failure.explain());
                            return;
                        case UNKNOWN:
                        case INTERNAL_ERROR:
                            setAttestationFailureReason(rc, failure, Collections.singletonMap("reason", attestationResult.getReason()));
                            Error(attestationResult.getReason(), 500, rc, failure.explain());
                            return;
                    }
                }

                if (json.containsKey("operator_type") && !operator.getOperatorType().name().equalsIgnoreCase(json.getString("operator_type"))) {
                    setAttestationFailureReason(rc, AttestationFailure.INVALID_TYPE, Collections.singletonMap("reason", AttestationFailure.INVALID_TYPE.explain()));
                    Error("attestation failure; invalid operator type", 403, rc, null);
                    return;
                }

                JsonObject responseObj = new JsonObject();
                EncryptedAttestationToken encryptedAttestationToken = attestationTokenService.createToken(token);

                try {
                    String attestationToken = encodeAttestationToken(rc, attestationResult, encryptedAttestationToken.getEncodedAttestationToken());
                    responseObj.put("attestation_token", attestationToken);
                    responseObj.put("expiresAt", encryptedAttestationToken.getExpiresAt());
                    responseObj.put("optout_url", ConfigStore.Global.get(Const.Config.OptOutUrlProp));

                    try {
                        Map.Entry<String, String> tokens = getJWTTokens(rc, profile, operator, attestationResult.getEnclaveId(), encryptedAttestationToken.getExpiresAt());
                        if (tokens != null) {
                            if (tokens.getKey() != null && !tokens.getKey().isBlank()) {
                                responseObj.put("attestation_jwt_optout", tokens.getKey());
                            }
                            if (tokens.getValue() != null && !tokens.getValue().isBlank()) {
                                responseObj.put("attestation_jwt_core", tokens.getValue());
                            }
                        }
                    } catch (Exception e) {
                        Boolean enforceJWT = ConfigStore.Global.getBoolean(EnforceJwtProp);
                        if (enforceJWT == null) {
                            enforceJWT = false;
                        }

                        if (enforceJWT) {
                            throw e;
                        } else {
                            logger.info("Failed creating the JWT, but enforceJWT is false. No JWTs returned.");
                        }
                    }
                } catch (Exception e) {
                    Error("attestation failure", 500, rc, AttestationFailure.INTERNAL_ERROR.explain());
                    return;
                }

                logger.info("attestation successful for SiteId: {}, Operator name: {}, protocol: {}", operator.getSiteId(), operator.getName(), protocol);
                Success(rc, responseObj);
            });
        } catch (AttestationService.NotFound e) {
            setAttestationFailureReason(rc, AttestationFailure.INVALID_PROTOCOL, Collections.singletonMap("cause", AttestationFailure.INVALID_PROTOCOL.explain()));
            Error("protocol not found", 403, rc, null);
        }
    }

    private static String encodeAttestationToken(RoutingContext rc, AttestationResult attestationResult, String encodedAttestationToken) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        if (attestationResult.getPublicKey() != null) {
            try {
                Cipher cipher = Cipher.getInstance(Const.Name.AsymetricEncryptionCipherClass);
                KeySpec keySpec = new X509EncodedKeySpec(attestationResult.getPublicKey());
                PublicKey publicKey = KeyFactory.getInstance(Const.Name.AsymetricEncryptionKeyClass).generatePublic(keySpec);
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                return Base64.getEncoder().encodeToString(cipher.doFinal(encodedAttestationToken.getBytes(StandardCharsets.UTF_8)));
            } catch (Exception e) {
                setAttestationFailureReason(rc, AttestationFailure.RESPONSE_ENCRYPTION_ERROR, Collections.singletonMap("exception", e.getMessage()));
                logger.warn("attestation failure: exception while encrypting response", e);
                throw e;
            }
        }

        return encodedAttestationToken;
    }

    private Map.Entry<String, String> getJWTTokens(RoutingContext rc, IAuthorizable profile, OperatorKey operator, String enclaveId, Instant expiresAt) throws JWTTokenProvider.JwtSigningException {
        String keyId = ConfigStore.Global.get(Const.Config.AwsKmsJwtSigningKeyIdProp);
        if (keyId != null && !keyId.isEmpty()) {
            try {
                String clientVersion = getClientVersionFromHeader(rc, profile);
                String optOutJwtToken = this.operatorJWTTokenProvider.getOptOutJWTToken(operator.getKeyHash(), operator.getName(), operator.getRoles(), operator.getSiteId(), enclaveId, operator.getProtocol(), clientVersion, expiresAt);
                String coreJwtToken = this.operatorJWTTokenProvider.getCoreJWTToken(operator.getKeyHash(), operator.getName(), operator.getRoles(), operator.getSiteId(), enclaveId, operator.getProtocol(), clientVersion, expiresAt);

                return new AbstractMap.SimpleEntry<>(optOutJwtToken, coreJwtToken);
            } catch (JWTTokenProvider.JwtSigningException e) {
                setAttestationFailureReason(rc, AttestationFailure.INTERNAL_ERROR, Collections.singletonMap("exception", e.getMessage()));
                logger.error("OptOut JWT token generation failed", e);
                throw e;
            }
        } else {
            logger.warn("OptOut JWT not set.");
        }
        return null;
    }

    private static void setAttestationFailureReason(RoutingContext context, AttestationFailure reason) {
        setAttestationFailureReason(context, reason, null);
    }

    private static void setAttestationFailureReason(RoutingContext context, AttestationFailure reason, Map<String, Object> data) {
        context.put(com.uid2.core.Const.RoutingContextData.ATTESTATION_FAILURE_REASON_PROP, reason);
        context.put(com.uid2.core.Const.RoutingContextData.ATTESTATION_FAILURE_DATA_PROP, data);
    }

    private void handleSiteRefresh(RoutingContext rc) {
        handleRefresh(rc, () -> {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            if (info.getOperatorType() != OperatorType.PUBLIC) {
                Error("error", 403, rc, "endpoint /sites/refresh is for public operators only");
                return null;
            }
            return siteMetadataProvider.getMetadata(info);
        }, "handleSiteRefresh", "sites");
    }

    private void handleSaltRefresh(RoutingContext rc) {
        handleRefresh(rc, () -> {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            return saltMetadataProvider.getMetadata(info);
        }, "handleSaltRefresh", "salt");
    }

    private void handleKeyRefresh(RoutingContext rc) {
        handleRefresh(rc, () -> {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            return keyMetadataProvider.getMetadata(info);
        }, "handleKeyRefresh", "key");
    }

    private void handleKeyAclRefresh(RoutingContext rc) {
        handleRefresh(rc, () -> {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            return keyAclMetadataProvider.getMetadata(info);
        }, "handleKeyAclRefresh", "key acl");
    }

    private void handleKeysetRefresh(RoutingContext rc) {
        handleRefresh(rc, () -> {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            return keysetMetadataProvider.getMetadata(info);
        }, "handleKeysetRefresh", "keyset");
    }

    private void handleKeysetKeyRefresh(RoutingContext rc) {
        handleRefresh(rc, () -> {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            return keysetKeyMetadataProvider.getMetadata(info);
        }, "handleKeysetKeyRefresh", "keyset key");
    }

    private void handleClientRefresh(RoutingContext rc) {
        handleRefresh(rc, () -> {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            return clientMetadataProvider.getMetadata(info);
        }, "handleClientRefresh", "client");
    }

    private void handleClientSideKeypairRefresh(RoutingContext rc) {
        handleRefresh(rc, () -> {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            if (info.getOperatorType() != OperatorType.PUBLIC) {
                Error("error", 403, rc, "endpoint /client_side_keypairs/refresh is for public operators only");
                return null;
            }
            return clientSideKeypairMetadataProvider.getMetadata(info);
        }, "handleClientSideKeypairRefresh", "client_side_keypairs");
    }

    private void handleServiceRefresh(RoutingContext rc) {
        handleRefresh(rc, () -> {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            if (info.getOperatorType() != OperatorType.PUBLIC) {
                Error("error", 403, rc, "endpoint /services/refresh is for public operators only");
                return null;
            }
            return serviceMetadataProvider.getMetadata();
        }, "handleServiceRefresh", "services");
    }

    private void handleServiceLinkRefresh(RoutingContext rc) {
        handleRefresh(rc, () -> {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            if (info.getOperatorType() != OperatorType.PUBLIC) {
                Error("error", 403, rc, "endpoint /service_links/refresh is for public operators only");
                return null;
            }
            return serviceLinkMetadataProvider.getMetadata();
        }, "handleServiceLinkRefresh", "service_links");
    }

    private void handleOperatorRefresh(RoutingContext rc) {
        handleRefresh(rc, () -> {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            return operatorMetadataProvider.getMetadata();
        }, "handleOperatorRefresh", "operator");
    }

    private void handlePartnerRefresh(RoutingContext rc) {
        handleRefresh(rc, () -> {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            return partnerMetadataProvider.getMetadata();
        }, "handlePartnerRefresh", "partner");
    }

    private void handleRefresh(RoutingContext rc, Callable<String> metadataFn, String refreshFunctionName, String refreshKeyName) {
        Future<String> future;
        try {
            future = vertx.executeBlocking(metadataFn);
        } catch (Exception e) {
            logger.warn("exception in {}: {}", refreshFunctionName, e.getMessage(), e);
            Error("error", 500, rc, String.format("error processing %s refresh", refreshKeyName));
            return;
        }

        future.onComplete(res -> {
            if (res.succeeded()) {
                if (!rc.response().ended()) {
                    rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                            .end(res.result());
                }
            } else {
                logger.warn("exception in {}: {}", refreshFunctionName, res.cause().getMessage(), res.cause());
                Error("error", 500, rc, String.format("error processing %s refresh", refreshKeyName));
            }
        });
    }

    private void handleEnclaveChange(RoutingContext rc, boolean isUnregister) {
        class Result {
            JsonObject make(String name, String failReason) {
                JsonObject o = new JsonObject();
                o.put("name", name);
                o.put("status", (failReason == null || failReason.isEmpty()) ? "success" : "failed");
                if (failReason != null && !failReason.isEmpty()) o.put("reason", failReason);
                return o;
            }
        }

        try {
            JsonObject main = rc.body().asJsonObject();

            if (!main.containsKey("enclaves")) {
                logger.info("enclave register has been called without .enclaves key");
                Error("error", 400, rc, "no .enclaves key in json payload");
                return;
            }

            Object enclavesObj = main.getValue("enclaves");
            if (!(enclavesObj instanceof JsonArray enclaves)) {
                logger.info("enclave register has been called without .enclaves key");
                Error("error", 400, rc, ".enclaves needs to be an array");
                return;
            }

            JsonArray res = new JsonArray();
            for (int i = 0; i < enclaves.size(); i++) {
                Result result = new Result();
                JsonObject item = enclaves.getJsonObject(i);
                String name = item.getString("name", "__item_" + String.valueOf(i));
                String protocol = item.getString("protocol", null);
                String identifier = item.getString("identifier", null);
                if (protocol == null) {
                    res.add(result.make(name, "no protocol provided"));
                    continue;
                } else if (identifier == null) {
                    res.add(result.make(name, "no identifier provided"));
                    continue;
                }

                try {
                    if (isUnregister) {
                        this.attestationService.unregisterEnclave(protocol, identifier);
                    } else {
                        this.attestationService.registerEnclave(protocol, identifier);
                    }
                } catch (AttestationService.NotFound notFound) {
                    res.add(result.make(name, "unknown protocol: " + protocol));
                    continue;
                } catch (AttestationException ex) {
                    res.add(result.make(name, "bad identifier"));
                    continue;
                }
                res.add(result.make(name, null));
            }

            rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(res.toString());
        } catch (Exception e) {
            logger.warn("exception in handleEnclaveRegister: " + e.getMessage(), e);
            Error("error", 500, rc, "error processing enclave register");
        }
    }

    private static String getClientVersionFromHeader(RoutingContext rc, IAuthorizable profile) {
        String clientVersion = "unknown client version";
        if (rc.request().headers().contains(Const.Http.AppVersionHeader)) {
            var client = VertxUtils.parseClientAppVersion(rc.request().headers().get(Const.Http.AppVersionHeader));
            if (client != null) {
                clientVersion = profile.getContact() + "|" + client.getKey() + "|" + client.getValue();
            } else {
                clientVersion = profile.getContact() + "|null client key";
            }
        }
        return clientVersion;
    }

    private void handleEnclaveRegister(RoutingContext rc) {
        handleEnclaveChange(rc, false);
    }

    private void handleEnclaveUnregister(RoutingContext rc) {
        handleEnclaveChange(rc, true);
    }

    void handleCloudEncryptionKeysRetrieval(RoutingContext rc) {
        try {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            int siteId = info.getSiteId();
            List<CloudEncryptionKey> cloudEncryptionKeys = cloudEncryptionKeyProvider.getKeys(siteId);

            if (cloudEncryptionKeys == null || cloudEncryptionKeys.isEmpty()) {
                Error("No Cloud Encryption keys found", 500, rc, "No Cloud Encryption keys found for siteId: " + siteId);
                return;
            }

            JsonObject response = new JsonObject()
                    .put("cloud_encryption_keys", new JsonArray(cloudEncryptionKeys));

            rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(response.encode());
        } catch (Exception e) {
            logger.error("Error in handleRefreshCloudEncryptionKeys: ", e);
            Error("error", 500, rc, "error generating attestation token");
        }
    }

    //region test endpoints
    private void handleTestGetAttestationToken(RoutingContext rc) {
        HttpMethod method = rc.request().method();
        if (method != HttpMethod.GET && method != HttpMethod.POST) {
            rc.response().setStatusCode(400).end();
        }

        try {
            JsonObject responseObj = new JsonObject();
            String attestationToken = attestationTokenService.createToken(
                    AuthMiddleware.getAuthToken(rc)).getEncodedAttestationToken();
            responseObj.put("attestation_token", attestationToken);
            Success(rc, responseObj);
        } catch (Exception e) {
            logger.warn("exception in handleTestGetAttestationToken: {}", e.getMessage());
            Error("error", 500, rc, "error generating attestation token");
        }
    }

    private void handleTestListEnclaves(RoutingContext rc) {
        HttpMethod method = rc.request().method();
        if (method != HttpMethod.GET && method != HttpMethod.POST) {
            rc.response().setStatusCode(400).end();
        }
        try {
            rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(new JsonArray(attestationService.listEnclaves()).toString());
        } catch (Exception e) {
            logger.warn("exception in handleTestListEnclaves: {}", e.getMessage());
            Error("error", 500, rc, "error getting enclave lists");
        }
    }
    //endregion test endpoints

    public static void Success(RoutingContext rc, Object body) {
        final JsonObject json = new JsonObject(new HashMap<>() {
            {
                put("status", "success");
                put("body", body);
            }
        });
        rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }

    public static void Error(String errorStatus, int statusCode, RoutingContext rc, String message) {
        final JsonObject json = new JsonObject(new HashMap<>() {
            {
                put("status", errorStatus);
            }
        });
        if (message != null) {
            json.put("message", message);
        }
        rc.response().setStatusCode(statusCode).putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }
}
