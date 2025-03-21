package com.uid2.core.util;

import com.uid2.core.model.ConfigStore;
import com.uid2.shared.auth.OperatorKey;
import com.uid2.shared.auth.OperatorType;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import static com.uid2.shared.Const.Http.AppVersionHeader;
import static com.uid2.shared.middleware.AuthMiddleware.API_CLIENT_PROP;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class OperatorInfoTest {

    @Mock
    private RoutingContext mockRoutingContext;

    @Mock
    private HttpServerRequest mockRequest;
    private static final String encryptionSupportVersion = "encryption_support_version";

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        ConfigStore.Global.load(new JsonObject().put(encryptionSupportVersion, "2.6"));
        when(mockRoutingContext.request()).thenReturn(mockRequest);
    }

    @Test
    void testConstructor() {
        OperatorInfo operatorInfo = new OperatorInfo(OperatorType.PRIVATE, 123, true);
        assertEquals(OperatorType.PRIVATE, operatorInfo.getOperatorType());
        assertEquals(123, operatorInfo.getSiteId());
        assertTrue(operatorInfo.getSupportsEncryption());
    }

    @Test
    void testGetOperatorInfo() throws Exception {
        OperatorKey mockOperatorKey = mock(OperatorKey.class);
        when(mockOperatorKey.getOperatorType()).thenReturn(OperatorType.PUBLIC);
        when(mockOperatorKey.getSiteId()).thenReturn(456);

        Map<String, Object> data = new HashMap<>();
        data.put(API_CLIENT_PROP, mockOperatorKey);
        when(mockRoutingContext.data()).thenReturn(data);
        when(mockRequest.getHeader("Encrypted")).thenReturn("true");
        OperatorInfo result = OperatorInfo.getOperatorInfo(mockRoutingContext);

        assertNotNull(result);
        assertEquals(OperatorType.PUBLIC, result.getOperatorType());
        assertEquals(456, result.getSiteId());
        assertTrue(result.getSupportsEncryption());
    }

    @Test
    void testGetOperatorInfoThrowsException() {
        Map<String, Object> data = new HashMap<>();
        data.put("api_client", "Invalid Object");
        when(mockRoutingContext.data()).thenReturn(data);

        assertThrows(Exception.class, () -> OperatorInfo.getOperatorInfo(mockRoutingContext));
    }

    @Test
    void testSupportsEncryptionTrue() {
        when(mockRequest.getHeader("Encrypted")).thenReturn("true");
        assertTrue(OperatorInfo.supportsEncryption(mockRoutingContext));
    }

    @Test
    void testSupportsEncryptionFalse() {
        when(mockRequest.getHeader(AppVersionHeader)).thenReturn("uid2-operator=1.0.0");
        assertFalse(OperatorInfo.supportsEncryption(mockRoutingContext));
    }

    @Test
    void testSupportsEncryptionMissingHeader() {
        when(mockRequest.getHeader(AppVersionHeader)).thenReturn(null);
        assertFalse(OperatorInfo.supportsEncryption(mockRoutingContext));
    }
}