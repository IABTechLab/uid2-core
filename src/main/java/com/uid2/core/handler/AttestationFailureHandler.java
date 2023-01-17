package com.uid2.core.handler;

import com.uid2.core.Const;
import com.uid2.core.vertx.AttestationFailureReason;
import com.uid2.shared.auth.IAuthorizable;
import com.uid2.shared.auth.OperatorKey;
import com.uid2.shared.middleware.AuthMiddleware;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

public class AttestationFailureHandler implements Handler<RoutingContext> {
    private static final Logger LOG = LoggerFactory.getLogger(AttestationFailureHandler.class);

    @Override
    public void handle(RoutingContext context) {
        context.addBodyEndHandler(v -> {
            if (context.response().getStatusCode() != 200) {
                logAttestationFailure(context);
            }
        });

        context.next();
    }

    private void logAttestationFailure(RoutingContext context) {
        final AttestationFailureReason attestationFailureReason = context.get(Const.RoutingContextData.ATTESTATION_FAILURE_REASON_PROP);
        final String attestationFailureDataJson = getAttestationFailureDataJson(context);

        final String operatorKeyHash = getOperatorKeyHash(context);

        final IAuthorizable profile = AuthMiddleware.getAuthClient(context);

        final OperatorKey operatorKey = profile instanceof OperatorKey ? (OperatorKey) profile : null;

        final String originatingIpAddress = getOriginatingIpAddress(context);

        LOG.warn("Attestation failed. StatusCode={} Reason={} Data={} OperatorKeyHash={} OperatorKeyName={} SiteId={} Protocol={} OperatorType={} OriginatingIpAddress={}",
                context.response().getStatusCode(),
                attestationFailureReason,
                attestationFailureDataJson,
                operatorKeyHash,
                operatorKey == null ? null : operatorKey.getName(),
                operatorKey == null ? null : operatorKey.getSiteId(),
                operatorKey == null ? null : operatorKey.getProtocol(),
                operatorKey == null ? null : operatorKey.getOperatorType(),
                originatingIpAddress,
                context.failure());
    }

    private static String getOperatorKeyHash(RoutingContext context) {
        // Take the operator key directly from the header, because
        // we won't have it in the context if authentication failed.
        final String authToken = AuthMiddleware.getAuthToken(context);

        return authToken == null ? null : DigestUtils.sha256Hex(authToken);
    }

    private static String getAttestationFailureDataJson(RoutingContext context) {
        final Map<String, Object> attestationFailureData = context.get(Const.RoutingContextData.ATTESTATION_FAILURE_DATA_PROP);

        if (attestationFailureData == null) {
            return "{}";
        }

        try {
            return new JsonObject(attestationFailureData).toString();
        } catch (Exception e) {
            LOG.error("Exception serializing attestation failure data", e);
            return "<Exception serializing data>";
        }
    }

    private static String getOriginatingIpAddress(RoutingContext context) {
        // When we upgrade to Vert.x 4, we can use router.allowForward(AllowForwardHeader.X_FORWARD) instead.
        // Then the originating IP address should be available in context.request().remoteAddress().hostAddress().
        final String originatingIpAddress = context.request().getHeader("X-Forwarded-For");

        if (originatingIpAddress != null) {
            return originatingIpAddress.split(",")[0];
        }

        return context.request().remoteAddress().host();
    }
}
