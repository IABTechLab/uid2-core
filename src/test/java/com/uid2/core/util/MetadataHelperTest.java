package com.uid2.core.util;

import com.uid2.core.model.ConfigStore;
import com.uid2.shared.auth.OperatorType;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;


public class MetadataHelperTest {

    @Mock
    private OperatorInfo operatorInfo;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        ConfigStore.Global.load(new JsonObject().put("provide_private_site_data", true));
    }

    @Test
    void testGetMetadataPathNameDecryptPublic() {
        when(operatorInfo.getOperatorType()).thenReturn(OperatorType.PUBLIC);
        when(operatorInfo.getSiteId()).thenReturn(42);
        when(operatorInfo.getSupportsEncryption()).thenReturn(true);

        String result = MetadataHelper.getMetadataPathName(operatorInfo, "s3://test-bucket/folder/");
        assertEquals("s3://test-bucket/encrypted/42_public/folder", result);
    }

    @Test
    void testGetMetadataPathNameDecryptPrivate() {
        when(operatorInfo.getOperatorType()).thenReturn(OperatorType.PRIVATE);
        when(operatorInfo.getSiteId()).thenReturn(42);
        when(operatorInfo.getSupportsEncryption()).thenReturn(true);

        String result = MetadataHelper.getMetadataPathName(operatorInfo, "s3://test-bucket/folder/");
        assertEquals("s3://test-bucket/encrypted/42_private/folder", result);
    }


    @Test
    void testGetMetadataPathNamePublic() {
        when(operatorInfo.getOperatorType()).thenReturn(OperatorType.PUBLIC);
        when(operatorInfo.getSiteId()).thenReturn(42);
        when(operatorInfo.getSupportsEncryption()).thenReturn(false);

        String result = MetadataHelper.getMetadataPathName(operatorInfo, "s3://test-bucket/folder/");
        assertEquals("s3://test-bucket/folder", result);
    }


    @Test
    void testGetMetadataPathNamePrivate() {
        when(operatorInfo.getOperatorType()).thenReturn(OperatorType.PRIVATE);
        when(operatorInfo.getSiteId()).thenReturn(42);
        when(operatorInfo.getSupportsEncryption()).thenReturn(false);

        String result = MetadataHelper.getMetadataPathName(operatorInfo, "s3://test-bucket/folder/");
        assertEquals("s3://test-bucket/site/42/folder", result);
    }
}
