package com.uid2.core.vertx;

import com.uid2.core.handler.AttestationFailureHandler;
import com.uid2.core.model.ConfigStore;
import com.uid2.core.service.*;
import com.uid2.core.util.OperatorInfo;
import com.uid2.shared.Const;

import com.uid2.shared.Utils;
import com.uid2.shared.attest.IAttestationTokenService;
import com.uid2.shared.auth.*;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.health.HealthComponent;
import com.uid2.shared.health.HealthManager;
import com.uid2.shared.middleware.AttestationMiddleware;
import com.uid2.shared.middleware.AuthMiddleware;
import com.uid2.shared.secure.*;
import com.uid2.shared.vertx.RequestCapturingHandler;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.CorsHandler;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class CoreVerticle extends AbstractVerticle {
    private static final Logger LOGGER = LoggerFactory.getLogger(CoreVerticle.class);

    private final HealthComponent healthComponent = HealthManager.instance.registerComponent("http-server");
    private final AuthMiddleware auth;
    private final AttestationService attestationService;
    private final AttestationMiddleware attestationMiddleware;
    private final IAuthorizableProvider authProvider;
    private final IEnclaveIdentifierProvider enclaveIdentifierProvider;

    private final IAttestationTokenService attestationTokenService;
    private final IClientMetadataProvider clientMetadataProvider;
    private final IOperatorMetadataProvider operatorMetadataProvider;
    private final IKeyMetadataProvider keyMetadataProvider;
    private final IKeyAclMetadataProvider keyAclMetadataProvider;
    private final ISaltMetadataProvider saltMetadataProvider;
    private final IPartnerMetadataProvider partnerMetadataProvider;

    public CoreVerticle(ICloudStorage cloudStorage,
                        IAuthorizableProvider authProvider,
                        AttestationService attestationService,
                        IAttestationTokenService attestationTokenService,
                        IEnclaveIdentifierProvider enclaveIdentifierProvider) throws Exception {
        this.healthComponent.setHealthStatus(false, "not started");

        this.authProvider = authProvider;

        this.attestationService = attestationService;
        this.attestationTokenService = attestationTokenService;
        this.enclaveIdentifierProvider = enclaveIdentifierProvider;
        this.enclaveIdentifierProvider.addListener(this.attestationService);

        this.attestationMiddleware = new AttestationMiddleware(this.attestationTokenService);

        this.auth = new AuthMiddleware(authProvider);

        this.clientMetadataProvider = new ClientMetadataProvider(cloudStorage);
        this.operatorMetadataProvider = new OperatorMetadataProvider(cloudStorage);
        this.keyMetadataProvider = new KeyMetadataProvider(cloudStorage);
        this.keyAclMetadataProvider = new KeyAclMetadataProvider(cloudStorage);
        this.saltMetadataProvider = new SaltMetadataProvider(cloudStorage);
        this.partnerMetadataProvider = new PartnerMetadataProvider(cloudStorage);
    }

    @Override
    public void start(Promise<Void> startPromise) {
        this.healthComponent.setHealthStatus(false, "still starting");

        final Router router = createRoutesSetup();

        final int portOffset = Utils.getPortOffset();
        final int port = Const.Port.ServicePortForCore + portOffset;
        vertx.createHttpServer()
                .requestHandler(router)
                .listen(port)
                .onSuccess(server -> {
                    this.healthComponent.setHealthStatus(true);
                    startPromise.complete();
                    LOGGER.info("Core verticle started on port: {}", server.actualPort());
                })
                .onFailure(e -> {
                    this.healthComponent.setHealthStatus(false, e.getMessage());
                    startPromise.fail(e);
                });
    }

    private Router createRoutesSetup() {
        final Router router = Router.router(vertx);

        router.route().handler(BodyHandler.create());
        router.route().handler(new RequestCapturingHandler());
        router.route().handler(CorsHandler.create(".*.")
                .allowedMethod(HttpMethod.GET)
                .allowedMethod(HttpMethod.POST)
                .allowedMethod(HttpMethod.OPTIONS)
                .allowedHeader("Access-Control-Request-Method")
                .allowedHeader("Access-Control-Allow-Credentials")
                .allowedHeader("Access-Control-Allow-Origin")
                .allowedHeader("Access-Control-Allow-Headers")
                .allowedHeader("Content-Type"));

        router.post("/attest")
                .handler(new AttestationFailureHandler())
                .handler(auth.handle(this::handleAttestAsync, Role.OPERATOR));
        router.get("/key/refresh").handler(auth.handle(attestationMiddleware.handle(this::handleKeyRefresh), Role.OPERATOR));
        router.get("/key/acl/refresh").handler(auth.handle(attestationMiddleware.handle(this::handleKeyAclRefresh), Role.OPERATOR));
        router.get("/salt/refresh").handler(auth.handle(attestationMiddleware.handle(this::handleSaltRefresh), Role.OPERATOR));
        router.get("/clients/refresh").handler(auth.handle(attestationMiddleware.handle(this::handleClientRefresh), Role.OPERATOR));
        router.get("/operators/refresh").handler(auth.handle(attestationMiddleware.handle(this::handleOperatorRefresh), Role.OPERATOR));
        router.get("/partners/refresh").handler(auth.handle(attestationMiddleware.handle(this::handlePartnerRefresh), Role.OPERATOR));
        router.get("/ops/healthcheck").handler(this::handleHealthCheck);

        if (Optional.ofNullable(ConfigStore.GLOBAL.getBoolean("enable_test_endpoints")).orElse(false)) {
            router.route("/attest/get_token").handler(auth.handle(this::handleTestGetAttestationToken, Role.OPERATOR));
        }

        return router;
    }

    private void handleHealthCheck(RoutingContext ctx) {
        if (HealthManager.instance.isHealthy()) {
            ctx.response().end("OK");
        } else {
            HttpServerResponse resp = ctx.response();
            String reason = HealthManager.instance.reason();
            resp.setStatusCode(503);
            resp.setChunked(true);
            resp.write(reason);
            resp.end();
        }
    }

    private void handleAttestAsync(RoutingContext ctx) {
        String token = AuthMiddleware.getAuthToken(ctx);
        IAuthorizable profile = authProvider.get(token);

        OperatorKey operator = (OperatorKey) profile;
        String protocol = operator.getProtocol();

        JsonObject json;
        try {
            json = ctx.getBodyAsJson();
        } catch (DecodeException e) {
            setAttestationFailureReason(ctx, AttestationFailureReason.REQUEST_BODY_IS_NOT_VALID_JSON);
            respondError("request body is not a valid json", 400, ctx, null);
            return;
        }

        String request = json == null ? null : json.getString("attestation_request");

        if(request == null || request.isEmpty()) {
            setAttestationFailureReason(ctx, AttestationFailureReason.NO_ATTESTATION_REQUEST_ATTACHED);
            respondError("no attestation_request attached", 400, ctx, null);
            return;
        }

        String clientPublicKey = json.getString("public_key", "");

        try {
            attestationService.attest(protocol, request, clientPublicKey, ar -> {
                if (!ar.succeeded()) {
                    setAttestationFailureReason(ctx, AttestationFailureReason.ATTESTATION_FAILURE, Collections.singletonMap("cause", ar.cause().getMessage()));
                    LOGGER.warn("attestation failure: ", ar.cause());
                    respondError("attestation failure", 500, ctx, null);
                    return;
                }

                final AttestationResult result = ar.result();
                if (!result.isSuccess()) {
                    setAttestationFailureReason(ctx, AttestationFailureReason.ATTESTATION_FAILURE, Collections.singletonMap("reason", result.getReason()));
                    respondError(result.getReason(), 401, ctx, null);
                    return;
                }

                JsonObject responseObj = new JsonObject();
                String attestationToken = attestationTokenService.createToken(token);

                if(result.getPublicKey() != null) {
                    try {
                        Cipher cipher = Cipher.getInstance(Const.Name.AsymetricEncryptionCipherClass);
                        KeySpec keySpec = new X509EncodedKeySpec(result.getPublicKey());
                        PublicKey publicKey = KeyFactory.getInstance(Const.Name.AsymetricEncryptionKeyClass).generatePublic(keySpec);
                        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                        attestationToken = Base64.getEncoder().encodeToString(cipher.doFinal(attestationToken.getBytes(StandardCharsets.UTF_8)));
                    } catch (Exception e) {
                        setAttestationFailureReason(ctx, AttestationFailureReason.RESPONSE_ENCRYPTION_EXCEPTION, Collections.singletonMap("exception", e.getMessage()));
                        LOGGER.warn("attestation failure: exception while encrypting response - " + e.getMessage(), e);
                        respondError("attestation failure", 500, ctx, null);
                        return;
                    }
                }

                // TODO: log requester identifier
                LOGGER.info("attestation successful");
                responseObj.put("attestation_token", attestationToken);
                respondSuccess(ctx, responseObj);
            });
        } catch (AttestationService.NotFound e) {
            setAttestationFailureReason(ctx, AttestationFailureReason.INVALID_PROTOCOL);
            respondError("protocol not found", 500, ctx, null);
        }
    }

    private static void setAttestationFailureReason(RoutingContext context, AttestationFailureReason reason) {
        setAttestationFailureReason(context, reason, null);
    }

    private static void setAttestationFailureReason(RoutingContext context, AttestationFailureReason reason, Map<String, Object> data) {
        context.put(com.uid2.core.Const.RoutingContextData.ATTESTATION_FAILURE_REASON_PROP, reason);
        context.put(com.uid2.core.Const.RoutingContextData.ATTESTATION_FAILURE_DATA_PROP, data);
    }

    private void handleSaltRefresh(RoutingContext ctx) {
        try {
            ctx.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(saltMetadataProvider.getMetadata());
        } catch (Exception e) {
            LOGGER.warn("exception in handleSaltRefresh: " + e.getMessage(), e);
            respondError("error", 500, ctx, "error processing salt refresh");
        }
    }

    private void handleKeyRefresh(RoutingContext ctx) {
        try {
            OperatorInfo info = OperatorInfo.getOperatorInfo(ctx);
            ctx.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(keyMetadataProvider.getMetadata(info));
        } catch (Exception e) {
            LOGGER.warn("exception in handleKeyRefresh: " + e.getMessage(), e);
            respondError("error", 500, ctx, "error processing key refresh");
        }
    }

    private void handleKeyAclRefresh(RoutingContext ctx) {
        try {
            OperatorInfo info = OperatorInfo.getOperatorInfo(ctx);
            ctx.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(keyAclMetadataProvider.getMetadata(info));
        } catch (Exception e) {
            LOGGER.warn("exception in handleKeyAclRefresh: " + e.getMessage(), e);
            respondError("error", 500, ctx, "error processing key acl refresh");
        }
    }

    private void handleClientRefresh(RoutingContext ctx) {
        try {
            OperatorInfo info = OperatorInfo.getOperatorInfo(ctx);
            ctx.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(clientMetadataProvider.getMetadata(info));
        } catch (Exception e) {
            LOGGER.warn("exception in handleClientRefresh: " + e.getMessage(), e);
            respondError("error", 500, ctx, "error processing client refresh");
        }
    }

    private void handleOperatorRefresh(RoutingContext ctx) {
        try {
            OperatorInfo info = OperatorInfo.getOperatorInfo(ctx);
            ctx.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(operatorMetadataProvider.getMetadata());
        } catch (Exception e) {
            LOGGER.warn("exception in handleOperatorRefresh: " + e.getMessage(), e);
            respondError("error", 500, ctx, "error processing operator refresh");
        }
    }

    private void handlePartnerRefresh(RoutingContext ctx) {
        try {
            OperatorInfo info = OperatorInfo.getOperatorInfo(ctx);
            ctx.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(partnerMetadataProvider.getMetadata());
        } catch (Exception e) {
            LOGGER.warn("exception in handlePartnerRefresh: " + e.getMessage(), e);
            respondError("error", 500, ctx, "error processing partner refresh");
        }
    }

    private void handleEnclaveChange(RoutingContext ctx, boolean isUnregister) {
        class Result {
            JsonObject make(String name, String failReason) {
                JsonObject o = new JsonObject();
                o.put("name", name);
                o.put("status", (failReason == null || failReason.isEmpty()) ? "success" : "failed");
                if(failReason != null && !failReason.isEmpty()) o.put("reason", failReason);
                return o;
            }
        }

        try {
            JsonObject main = ctx.getBodyAsJson();

            if(!main.containsKey("enclaves")) {
                LOGGER.info("enclave register has been called without .enclaves key");
                respondError("error", 400, ctx, "no .enclaves key in json payload");
                return;
            }

            Object enclavesObj = main.getValue("enclaves");
            if(!(enclavesObj instanceof JsonArray)) {
                LOGGER.info("enclave register has been called without .enclaves key");
                respondError("error", 400, ctx, ".enclaves needs to be an array");
                return;
            }

            JsonArray res = new JsonArray();
            JsonArray enclaves = (JsonArray) enclavesObj;
            for (int i=0;i<enclaves.size();i++) {
                Result result = new Result();
                JsonObject item = enclaves.getJsonObject(i);
                String name = item.getString("name", "__item_" + String.valueOf(i));
                String proto = item.getString("protocol", null);
                String identifier = item.getString("identifier", null);
                if(proto == null) {
                    res.add(result.make(name, "no protocol provided"));
                    continue;
                } else if (identifier == null) {
                    res.add(result.make(name, "no identifier provided"));
                    continue;
                }

                try {
                    if(isUnregister) {
                        this.attestationService.unregisterEnclave(proto, identifier);
                    } else {
                        this.attestationService.registerEnclave(proto, identifier);
                    }
                } catch (AttestationService.NotFound notFound) {
                    res.add(result.make(name, "unknown protocol: " + proto));
                    continue;
                } catch (AttestationException e) {
                    res.add(result.make(name, "bad identifier"));
                    continue;
                }
                res.add(result.make(name, null));
            }

            ctx.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(res.toString());
        } catch (Exception e) {
            LOGGER.warn("exception in handleEnclaveRegister: " + e.getMessage(), e);
            respondError("error", 500, ctx, "error processing enclave register");
        }
    }

    private void handleEnclaveRegister(RoutingContext ctx) {
        handleEnclaveChange(ctx, false);
    }

    private void handleEnclaveUnregister(RoutingContext ctx) {
        handleEnclaveChange(ctx, true);
    }

    //region test endpoints
    private void handleTestGetAttestationToken(RoutingContext ctx) {
        HttpMethod method = ctx.request().method();
        if (method != HttpMethod.GET && method != HttpMethod.POST) {
            ctx.response().setStatusCode(400).end();
        }

        try {
            JsonObject responseObj = new JsonObject();
            String attestationToken = attestationTokenService.createToken(
                    AuthMiddleware.getAuthToken(ctx));
            responseObj.put("attestation_token", attestationToken);
            respondSuccess(ctx, responseObj);
        } catch (Exception e) {
            LOGGER.warn("exception in handleTestGetAttestationToken: {}", e.getMessage());
            respondError("error", 500, ctx, "error generating attestation token");
        }
    }

    private void handleTestListEnclaves(RoutingContext ctx) {
        HttpMethod method = ctx.request().method();
        if (method != HttpMethod.GET && method != HttpMethod.POST) {
            ctx.response().setStatusCode(400).end();
        }
        try {
            ctx.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(new JsonArray(attestationService.listEnclaves()).toString());
        } catch (Exception e) {
            LOGGER.warn("exception in handleTestListEnclaves: {}", e.getMessage());
            respondError("error", 500, ctx, "error getting enclave lists");
        }
    }
    //endregion test endpoints

    public static void respondSuccess(RoutingContext ctx, Object body) {
        final JsonObject json = new JsonObject(new HashMap<String, Object>() {
            {
                put("status", "success");
                put("body", body);
            }
        });
        ctx.response()
                .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }

    public static void respondError(String errorStatus, int statusCode, RoutingContext ctx, String message) {
        final JsonObject json = new JsonObject(new HashMap<String, Object>() {
            {
                put("status", errorStatus);
            }
        });
        if (message != null) {
            json.put("message", message);
        }
        ctx.response()
                .setStatusCode(statusCode)
                .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }
}
