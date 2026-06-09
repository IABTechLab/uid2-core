package com.uid2.core.handler;

import com.uid2.shared.auth.IAuthorizable;
import com.uid2.shared.middleware.AuthMiddleware;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.HttpURLConnection;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class GenericFailureHandlerTest {

    // Drives the handler for a given status code + resolved auth profile, returning the response body written.
    private static String handleAndCaptureBody(int statusCode, IAuthorizable profile) {
        RoutingContext ctx = mock(RoutingContext.class);
        HttpServerResponse response = mock(HttpServerResponse.class);

        Map<String, Object> data = new HashMap<>();
        if (profile != null) {
            data.put(AuthMiddleware.API_CLIENT_PROP, profile);
        }

        when(ctx.statusCode()).thenReturn(statusCode);
        when(ctx.response()).thenReturn(response);
        when(ctx.normalizedPath()).thenReturn("/attest");
        when(ctx.failure()).thenReturn(null);
        when(ctx.data()).thenReturn(data);

        when(response.ended()).thenReturn(false);
        when(response.closed()).thenReturn(false);
        when(response.putHeader(anyString(), anyString())).thenReturn(response);
        when(response.setStatusCode(anyInt())).thenReturn(response);

        new GenericFailureHandler().handle(ctx);

        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(response).end(bodyCaptor.capture());
        return bodyCaptor.getValue();
    }

    @Test
    void unknownKeyReturnsUnrecognizedKeyReason() {
        // No auth profile resolved -> key was not recognized (the 4eyes.ai transcription-error case).
        JsonObject body = new JsonObject(handleAndCaptureBody(HttpURLConnection.HTTP_UNAUTHORIZED, null));

        assertEquals("unauthorized", body.getString("status"));
        assertEquals("unrecognized_key", body.getString("reason"));
        assertTrue(body.getString("message").toLowerCase().contains("not recognized"));
    }

    @Test
    void disabledKeyReturnsKeyDisabledReason() {
        IAuthorizable disabledKey = mock(IAuthorizable.class);
        when(disabledKey.isDisabled()).thenReturn(true);

        JsonObject body = new JsonObject(handleAndCaptureBody(HttpURLConnection.HTTP_UNAUTHORIZED, disabledKey));

        assertEquals("unauthorized", body.getString("status"));
        assertEquals("key_disabled", body.getString("reason"));
        assertTrue(body.getString("message").toLowerCase().contains("disabled"));
    }

    @Test
    void recognizedButUnauthorizedKeyReturnsInsufficientRoleReason() {
        IAuthorizable wrongRoleKey = mock(IAuthorizable.class);
        when(wrongRoleKey.isDisabled()).thenReturn(false);

        JsonObject body = new JsonObject(handleAndCaptureBody(HttpURLConnection.HTTP_UNAUTHORIZED, wrongRoleKey));

        assertEquals("unauthorized", body.getString("status"));
        assertEquals("insufficient_role", body.getString("reason"));
    }

    @Test
    void nonUnauthorizedStatusKeepsPlainReasonPhrase() {
        // Non-401 failures must keep the existing bare reason-phrase body (no behaviour change).
        String body = handleAndCaptureBody(HttpURLConnection.HTTP_BAD_REQUEST, null);

        assertEquals("Bad Request", body);
    }
}
