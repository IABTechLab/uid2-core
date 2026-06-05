package com.uid2.core.handler;

import com.uid2.shared.auth.IAuthorizable;
import com.uid2.shared.auth.OperatorKey;
import com.uid2.shared.middleware.AuthMiddleware;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpClosedException;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.apache.http.impl.EnglishReasonPhraseCatalog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.HttpURLConnection;

public class GenericFailureHandler implements Handler<RoutingContext> {
    private static final Logger LOGGER = LoggerFactory.getLogger(GenericFailureHandler.class);

    @Override
    public void handle(RoutingContext ctx) {
        // Status code will be 500 for the RuntimeException
        int statusCode = ctx.statusCode();
        HttpServerResponse response = ctx.response();
        String url = ctx.normalizedPath();
        Throwable t = ctx.failure();

        final IAuthorizable profile = AuthMiddleware.getAuthClient(ctx);
        final OperatorKey operatorKey = profile instanceof OperatorKey ? (OperatorKey) profile : null;
        String participant = "unknown";
        if (operatorKey != null) {
            participant = operatorKey.getName();
        }

        if (t != null) {
            if (statusCode >= 500 && statusCode < 600) { // 5xx is server error, so error
                LOGGER.error("URL: [{}], Participant: [{}] - Error response code: [{}] - Error:", url, participant, statusCode, t);
            } else if (statusCode >= 400 && statusCode < 500) { // 4xx is user error, so just warn
                LOGGER.warn("URL: [{}], Participant: [{}] - Error response code: [{}] - Error:", url, participant, statusCode, t);
            }
        }

        if (!response.ended() && !response.closed()) {
            if (statusCode == HttpURLConnection.HTTP_UNAUTHORIZED) {
                // Return the specific reason so the caller (e.g. a private operator at startup) 
                // gets an actionable message.
                response.putHeader("Content-Type", "application/json")
                        .setStatusCode(statusCode)
                        .end(buildUnauthorizedBody(profile).encode());
            } else {
                response.setStatusCode(statusCode)
                        .end(EnglishReasonPhraseCatalog.INSTANCE.getReason(statusCode, null));
            }
        }
    }

    private static JsonObject buildUnauthorizedBody(IAuthorizable profile) {
        final String reason;
        final String message;
        if (profile == null) {
            // Key did not resolve to any record.
            reason = "unrecognized_key";
            message = "Operator key not recognized.";
        } else if (profile.isDisabled()) {
            reason = "key_disabled";
            message = "Operator key is recognized but has been disabled.";
        } else {
            reason = "insufficient_role";
            message = "Operator key is recognized but is not authorized for this operation.";
        }
        return new JsonObject()
                .put("status", "unauthorized")
                .put("reason", reason)
                .put("message", message);
    }
}
