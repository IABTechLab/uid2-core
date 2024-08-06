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

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(mockRoutingContext.request()).thenReturn(mockRequest);
        ConfigStore.Global.load(new JsonObject().put("encryption_support_version", "2.6"));
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
        when(mockRequest.getHeader(AppVersionHeader)).thenReturn("uid2-operator=3.0.0");

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
        when(mockRequest.getHeader(AppVersionHeader)).thenReturn("uid2-operator=3.0.0");
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

    @Test
    void testIsVersionGreaterOrEqual() {
        assertTrue(OperatorInfo.isVersionGreaterOrEqual("2.0.0", "1.0.0"));
        assertTrue(OperatorInfo.isVersionGreaterOrEqual("2.0.0", "2.0.0"));
        assertFalse(OperatorInfo.isVersionGreaterOrEqual("1.0.0", "2.0.0"));
        assertTrue(OperatorInfo.isVersionGreaterOrEqual("2.1.0", "2.0.0"));
        assertFalse(OperatorInfo.isVersionGreaterOrEqual("2.0.1", "2.1.0"));
    }
}