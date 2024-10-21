package com.uid2.core.handler;

import com.uid2.core.Const;
import com.uid2.shared.auth.IAuthorizable;
import com.uid2.shared.auth.OperatorKey;
import com.uid2.shared.middleware.AuthMiddleware;
import com.uid2.shared.secure.AttestationFailure;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.SocketAddress;
import io.vertx.ext.web.RoutingContext;
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
        final IAuthorizable profile = AuthMiddleware.getAuthClient(context);

        final OperatorKey operatorKey = profile instanceof OperatorKey ? (OperatorKey) profile : null;

        if (operatorKey == null) {
            if (context.response().getStatusCode() == 401)  {
                LOG.warn("Attestation failed. Reason={invalid operator key}");
            }
            return;
        }

        final AttestationFailure attestationFailure = context.get(Const.RoutingContextData.ATTESTATION_FAILURE_REASON_PROP);
        final String attestationFailureDataJson = getAttestationFailureDataJson(context);

        final String originatingIpAddress = getOriginatingIpAddress(context);

        LOG.warn("Attestation failed. StatusCode={} Reason={} Data={} OperatorKeyHash={} OperatorKeyName={} SiteId={} Protocol={} OperatorType={} OriginatingIpAddress={}",
                context.response().getStatusCode(),
                attestationFailure,
                attestationFailureDataJson,
                operatorKey.getKeyHash(),
                operatorKey.getName(),
                operatorKey.getSiteId(),
                operatorKey.getProtocol(),
                operatorKey.getOperatorType(),
                originatingIpAddress,
                context.failure());
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

        final SocketAddress remoteAddress = context.request().remoteAddress();
        return remoteAddress == null ? null : remoteAddress.host();
    }
}
