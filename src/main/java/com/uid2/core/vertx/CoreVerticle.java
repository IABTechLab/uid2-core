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
import io.vertx.core.Promise;
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
import io.vertx.ext.web.handler.BodyHandler;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.uid2.shared.store.reader.RotatingS3KeyProvider;
import com.uid2.shared.model.S3Key;

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
    private final ISiteMetadataProvider siteMetadataProvider;
    private final IClientMetadataProvider clientMetadataProvider;
    private final IClientSideKeypairMetadataProvider clientSideKeypairMetadataProvider;
    private final IServiceMetadataProvider serviceMetadataProvider;
    private final IServiceLinkMetadataProvider serviceLinkMetadataProvider;
    private final IOperatorMetadataProvider operatorMetadataProvider;
    private final IKeyMetadataProvider keyMetadataProvider;
    private final IKeyAclMetadataProvider keyAclMetadataProvider;
    private final IKeysetMetadataProvider keysetMetadataProvider;
    private final IKeysetKeyMetadataProvider keysetKeyMetadataProvider;
    private final ISaltMetadataProvider saltMetadataProvider;
    private final IPartnerMetadataProvider partnerMetadataProvider;
    private final OperatorJWTTokenProvider operatorJWTTokenProvider;
    private final JwtService jwtService;
    private final RotatingS3KeyProvider s3KeyProvider;
    private static final String ENCRYPTION_SUPPORT_VERSION = "2.3"; // Set this to the appropriate version later

    public CoreVerticle(ICloudStorage cloudStorage,
                        IAuthorizableProvider authProvider,
                        AttestationService attestationService,
                        IAttestationTokenService attestationTokenService,
                        IEnclaveIdentifierProvider enclaveIdentifierProvider,
                        OperatorJWTTokenProvider operatorJWTTokenProvider,
                        JwtService jwtService,
                        RotatingS3KeyProvider s3KeyProvider) throws Exception {
        this.operatorJWTTokenProvider = operatorJWTTokenProvider;
        this.healthComponent.setHealthStatus(false, "not started");

        this.authProvider = authProvider;

        this.attestationService = attestationService;
        this.attestationTokenService = attestationTokenService;
        this.jwtService = jwtService;
        this.enclaveIdentifierProvider = enclaveIdentifierProvider;
        this.enclaveIdentifierProvider.addListener(this.attestationService);
        this.s3KeyProvider = s3KeyProvider;


        final String jwtAudience = ConfigStore.Global.get(Const.Config.CorePublicUrlProp);
        final String jwtIssuer = ConfigStore.Global.get(Const.Config.CorePublicUrlProp);
        Boolean enforceJwt = ConfigStore.Global.getBoolean(Const.Config.EnforceJwtProp);
        if (enforceJwt == null) {
            enforceJwt = false;
        }

        this.attestationMiddleware = new AttestationMiddleware(this.attestationTokenService, this.jwtService, jwtAudience, jwtIssuer, enforceJwt);

        this.auth = new AuthMiddleware(authProvider);

        this.siteMetadataProvider = new SiteMetadataProvider(cloudStorage);
        this.clientMetadataProvider = new ClientMetadataProvider(cloudStorage);
        this.operatorMetadataProvider = new OperatorMetadataProvider(cloudStorage);
        this.keyMetadataProvider = new KeyMetadataProvider(cloudStorage);
        this.keyAclMetadataProvider = new KeyAclMetadataProvider(cloudStorage);
        this.saltMetadataProvider = new SaltMetadataProvider(cloudStorage);
        this.partnerMetadataProvider = new PartnerMetadataProvider(cloudStorage);
        this.keysetMetadataProvider = new KeysetMetadataProvider(cloudStorage);
        this.keysetKeyMetadataProvider = new KeysetKeysMetadataProvider(cloudStorage);
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
                        JwtService jwtService) throws Exception {
        this(cloudStorage, authorizableProvider, attestationService, attestationTokenService, enclaveIdentifierProvider, jwtTokenProvider, jwtService, null);
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

        router.post("/attest")
                .handler(new AttestationFailureHandler())
                .handler(auth.handle(this::handleAttestAsync, Role.OPERATOR, Role.OPTOUT_SERVICE));
        router.get("/s3encryption_keys/retrieve").handler(auth.handle(attestationMiddleware.handle(this::handleS3EncryptionKeysRetrieval), Role.OPERATOR));
        router.get("/sites/refresh").handler(auth.handle(attestationMiddleware.handle(this::handleSiteRefresh), Role.OPERATOR));
        router.get("/key/refresh").handler(auth.handle(attestationMiddleware.handle(this::handleKeyRefresh), Role.OPERATOR));
        router.get("/key/acl/refresh").handler(auth.handle(attestationMiddleware.handle(this::handleKeyAclRefresh), Role.OPERATOR));
        router.get("/key/keyset/refresh").handler(auth.handle(attestationMiddleware.handle(this::handleKeysetRefresh), Role.OPERATOR));
        router.get("/key/keyset-keys/refresh").handler(auth.handle(attestationMiddleware.handle(this::handleKeysetKeyRefresh), Role.OPERATOR));
        router.get("/salt/refresh").handler(auth.handle(attestationMiddleware.handle(this::handleSaltRefresh), Role.OPERATOR));
        router.get("/clients/refresh").handler(auth.handle(attestationMiddleware.handle(this::handleClientRefresh), Role.OPERATOR));
        router.get("/client_side_keypairs/refresh").handler(auth.handle(attestationMiddleware.handle(this::handleClientSideKeypairRefresh), Role.OPERATOR));
        router.get("/services/refresh").handler(auth.handle(attestationMiddleware.handle(this::handleServiceRefresh), Role.OPERATOR));
        router.get("/service_links/refresh").handler(auth.handle(attestationMiddleware.handle(this::handleServiceLinkRefresh), Role.OPERATOR));
        router.get("/operators/refresh").handler(auth.handle(attestationMiddleware.handle(this::handleOperatorRefresh), Role.OPTOUT_SERVICE));
        router.get("/partners/refresh").handler(auth.handle(attestationMiddleware.handle(this::handlePartnerRefresh), Role.OPTOUT_SERVICE));
        router.get("/ops/healthcheck").handler(this::handleHealthCheck);

        if (Optional.ofNullable(ConfigStore.Global.getBoolean("enable_test_endpoints")).orElse(false)) {
            router.route("/attest/get_token").handler(auth.handle(this::handleTestGetAttestationToken, Role.OPERATOR));
        }

        return router;
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
            setAttestationFailureReason(rc, AttestationFailureReason.REQUEST_BODY_IS_NOT_VALID_JSON);
            Error("request body is not a valid json", 400, rc, null);
            return;
        }

        String request = json == null ? null : json.getString("attestation_request");

        if (request == null || request.isEmpty()) {
            setAttestationFailureReason(rc, AttestationFailureReason.NO_ATTESTATION_REQUEST_ATTACHED);
            Error("no attestation_request attached", 400, rc, null);
            return;
        }

        String clientPublicKey = json.getString("public_key", "");

        try {
            attestationService.attest(protocol, request, clientPublicKey, ar -> {
                if (!ar.succeeded()) {
                    setAttestationFailureReason(rc, AttestationFailureReason.ATTESTATION_FAILURE, Collections.singletonMap("cause", ar.cause().getMessage()));
                    logger.warn("attestation failure: ", ar.cause());
                    Error("attestation failure", 500, rc, null);
                    return;
                }

                final AttestationResult attestationResult = ar.result();
                if (!attestationResult.isSuccess()) {
                    setAttestationFailureReason(rc, AttestationFailureReason.ATTESTATION_FAILURE, Collections.singletonMap("reason", attestationResult.getReason()));
                    Error(attestationResult.getReason(), 401, rc, null);
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
                    Error("attestation failure", 500, rc, null);
                    return;
                }

                logger.info("attestation successful for SiteId: {}, Operator name: {}, protocol: {}", operator.getSiteId(), operator.getName(), protocol);
                Success(rc, responseObj);
            });
        } catch (AttestationService.NotFound e) {
            setAttestationFailureReason(rc, AttestationFailureReason.INVALID_PROTOCOL);
            Error("protocol not found", 500, rc, null);
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
                setAttestationFailureReason(rc, AttestationFailureReason.RESPONSE_ENCRYPTION_EXCEPTION, Collections.singletonMap("exception", e.getMessage()));
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

                Map.Entry<String, String> tokens = new AbstractMap.SimpleEntry<>(optOutJwtToken, coreJwtToken);
                return tokens;
            } catch (JWTTokenProvider.JwtSigningException e) {
                setAttestationFailureReason(rc, AttestationFailureReason.INTERNAL_ERROR, Collections.singletonMap("exception", e.getMessage()));
                logger.error("OptOut JWT token generation failed", e);
                throw e;
            }
        } else {
            logger.warn("OptOut JWT not set.");
        }
        return null;
    }

    private static void setAttestationFailureReason(RoutingContext context, AttestationFailureReason reason) {
        setAttestationFailureReason(context, reason, null);
    }

    private static void setAttestationFailureReason(RoutingContext context, AttestationFailureReason reason, Map<String, Object> data) {
        context.put(com.uid2.core.Const.RoutingContextData.ATTESTATION_FAILURE_REASON_PROP, reason);
        context.put(com.uid2.core.Const.RoutingContextData.ATTESTATION_FAILURE_DATA_PROP, data);
    }

    private void handleSiteRefresh(RoutingContext rc) {
        try {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            if (info.getOperatorType() != OperatorType.PUBLIC) {
                Error("error", 403, rc, "endpoint /sites/refresh is for public operators only");
                return;
            }
            rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(siteMetadataProvider.getMetadata());
        } catch (Exception e) {
            logger.warn("exception in handleSiteRefresh: " + e.getMessage(), e);
            Error("error", 500, rc, "error processing sites refresh");
        }
    }

    private void handleSaltRefresh(RoutingContext rc) {
        try {
            rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(saltMetadataProvider.getMetadata());
        } catch (Exception e) {
            logger.warn("exception in handleSaltRefresh: " + e.getMessage(), e);
            Error("error", 500, rc, "error processing salt refresh");
        }
    }

    private void handleKeyRefresh(RoutingContext rc) {
        try {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            boolean includeEncrypted = isEncryptionSupported(rc);
            rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(keyMetadataProvider.getMetadata(info, includeEncrypted));
        } catch (Exception e) {
            logger.warn("exception in handleKeyRefresh: " + e.getMessage(), e);
            Error("error", 500, rc, "error processing key refresh");
        }
    }

    private void handleKeyAclRefresh(RoutingContext rc) {
        try {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            boolean includeEncrypted = isEncryptionSupported(rc);
            rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(keyAclMetadataProvider.getMetadata(info, includeEncrypted));
        } catch (Exception e) {
            logger.warn("exception in handleKeyAclRefresh: " + e.getMessage(), e);
            Error("error", 500, rc, "error processing key acl refresh");
        }
    }

    private void handleKeysetRefresh(RoutingContext rc) {
        try {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            boolean includeEncrypted = isEncryptionSupported(rc);
            rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(keysetMetadataProvider.getMetadata(info, includeEncrypted));
        } catch (Exception e) {
            logger.warn("exception in handleKeysetRefresh: " + e.getMessage(), e);
            Error("error", 500, rc, "error processing key refresh");
        }
    }

    private void handleKeysetKeyRefresh(RoutingContext rc) {
        try {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            boolean includeEncrypted = isEncryptionSupported(rc);
            rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(keysetKeyMetadataProvider.getMetadata(info, includeEncrypted));
        } catch (Exception e) {
            logger.warn("exception in handleKeysetKeyRefresh: " + e.getMessage(), e);
            Error("error", 500, rc, "error processing key refresh");
        }
    }

    private void handleClientRefresh(RoutingContext rc) {
        try {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            boolean includeEncrypted = isEncryptionSupported(rc);
            rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(clientMetadataProvider.getMetadata(info, includeEncrypted));
        } catch (Exception e) {
            logger.warn("exception in handleClientRefresh: " + e.getMessage(), e);
            Error("error", 500, rc, "error processing client refresh");
        }
    }

    private void handleClientSideKeypairRefresh(RoutingContext rc) {
        try {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            if (info.getOperatorType() != OperatorType.PUBLIC) {
                Error("error", 403, rc, "endpoint /client_side_keypairs/refresh is for public operators only");
                return;
            }
            rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(clientSideKeypairMetadataProvider.getMetadata());
        } catch (Exception e) {
            logger.warn("exception in handleClientSideKeypairRefresh: " + e.getMessage(), e);
            Error("error", 500, rc, "error processing client_side_keypairs refresh");
        }
    }

    private void handleServiceRefresh(RoutingContext rc) {
        try {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            if (info.getOperatorType() != OperatorType.PUBLIC) {
                Error("error", 403, rc, "endpoint /services/refresh is for public operators only");
                return;
            }
            rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(serviceMetadataProvider.getMetadata());
        } catch (Exception e) {
            logger.warn("exception in handleServiceRefresh: " + e.getMessage(), e);
            Error("error", 500, rc, "error processing services refresh");
        }
    }

    private void handleServiceLinkRefresh(RoutingContext rc) {
        try {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            if (info.getOperatorType() != OperatorType.PUBLIC) {
                Error("error", 403, rc, "endpoint /service_links/refresh is for public operators only");
                return;
            }
            rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(serviceLinkMetadataProvider.getMetadata());
        } catch (Exception e) {
            logger.warn("exception in handleServiceLinkRefresh: " + e.getMessage(), e);
            Error("error", 500, rc, "error processing service_links refresh");
        }
    }

    private void handleOperatorRefresh(RoutingContext rc) {
        try {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(operatorMetadataProvider.getMetadata());
        } catch (Exception e) {
            logger.warn("exception in handleOperatorRefresh: " + e.getMessage(), e);
            Error("error", 500, rc, "error processing operator refresh");
        }
    }

    private void handlePartnerRefresh(RoutingContext rc) {
        try {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(partnerMetadataProvider.getMetadata());
        } catch (Exception e) {
            logger.warn("exception in handlePartnerRefresh: " + e.getMessage(), e);
            Error("error", 500, rc, "error processing partner refresh");
        }
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
            if (!(enclavesObj instanceof JsonArray)) {
                logger.info("enclave register has been called without .enclaves key");
                Error("error", 400, rc, ".enclaves needs to be an array");
                return;
            }

            JsonArray res = new JsonArray();
            JsonArray enclaves = (JsonArray) enclavesObj;
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
            clientVersion = profile.getContact() + "|" + client.getKey() + "|" + client.getValue();
        }
        return clientVersion;
    }

    private void handleEnclaveRegister(RoutingContext rc) {
        handleEnclaveChange(rc, false);
    }

    private void handleEnclaveUnregister(RoutingContext rc) {
        handleEnclaveChange(rc, true);
    }

    void handleS3EncryptionKeysRetrieval(RoutingContext rc) {
        try {
            OperatorInfo info = OperatorInfo.getOperatorInfo(rc);
            int siteId = info.getSiteId();

            List<S3Key> s3Keys = s3KeyProvider.getKeysForSiteFromMap(siteId);

            if (s3Keys == null || s3Keys.isEmpty()) {
                Error("No S3 keys found", 500, rc, "No S3 keys found for siteId: " + siteId);
                return;
            }

            JsonObject response = new JsonObject()
                    .put("s3Keys", new JsonArray(s3Keys));

            rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(response.encode());
        } catch (Exception e) {
            logger.error("Error in handleRefreshS3Keys: ", e);
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
        final JsonObject json = new JsonObject(new HashMap<String, Object>() {
            {
                put("status", "success");
                put("body", body);
            }
        });
        rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }

    public static void Error(String errorStatus, int statusCode, RoutingContext rc, String message) {
        final JsonObject json = new JsonObject(new HashMap<String, Object>() {
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

    private boolean isEncryptionSupported(RoutingContext context) {
        String appVersion = context.request().getHeader(Const.Http.AppVersionHeader);
        if (appVersion == null) return false;
        String[] versions = appVersion.split(";");
        for (String version : versions) {
            if (version.startsWith("uid2-operator=")) {
                String operatorVersion = version.substring("uid2-operator=".length());
                return isVersionGreaterOrEqual(operatorVersion, ENCRYPTION_SUPPORT_VERSION);
            }
        }
        return false;
    }

    private boolean isVersionGreaterOrEqual(String fullVersionString, String minVersion) {
        // Extract uid2-operator version
        String v1 = extractOperatorVersion(fullVersionString);
        String v2 = minVersion;

        // Remove -SNAPSHOT or any other suffixes
        v1 = v1.split("-")[0];
        v2 = v2.split("-")[0];

        Pattern pattern = Pattern.compile("(\\d+)\\.(\\d+)\\.(\\d+)");
        Matcher m1 = pattern.matcher(v1);
        Matcher m2 = pattern.matcher(v2);

        if (!m1.find() || !m2.find()) {
            return false; // Invalid version format
        }

        for (int i = 1; i <= 3; i++) {
            int num1 = Integer.parseInt(m1.group(i));
            int num2 = Integer.parseInt(m2.group(i));
            if (num1 > num2) {
                return true;
            } else if (num1 < num2) {
                return false;
            }
        }

        return true; // Versions are equal
    }

    private String extractOperatorVersion(String fullVersionString) {
        String[] parts = fullVersionString.split(";");
        for (String part : parts) {
            if (part.startsWith("uid2-operator=")) {
                return part.substring("uid2-operator=".length());
            }
        }
        return "";
    }
}
