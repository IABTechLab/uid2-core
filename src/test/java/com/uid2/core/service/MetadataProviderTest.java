package com.uid2.core.service;

import com.uid2.core.model.SecretStore;
import com.uid2.core.util.OperatorInfo;
import com.uid2.shared.auth.OperatorType;
import com.uid2.shared.cloud.ICloudStorage;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.ByteArrayInputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class MetadataProviderTest {
    @Mock private ICloudStorage metadataStreamProvider;
    @Mock private ICloudStorage downloadUrlGenerator;
    private MockMetadataProvider metadataProvider;

    @BeforeAll
    public static void setupAll() {
        SecretStore.Global.load(new JsonObject("{\"mocks_metadata_path\":\"mocks/metadata.json\",\"arraymocks_metadata_path\":\"arraymocks/metadata.json\"}"));
    }

    @AfterAll
    public static void teardownAll() {
        SecretStore.Global.load(new JsonObject());
    }

    @BeforeEach
    public void setup() throws Exception {
        MockitoAnnotations.openMocks(this);
        when(metadataStreamProvider.download(eq("mocks/metadata.json"))).thenReturn(new ByteArrayInputStream("{\"mocks\":{\"location\":\"mocks3path/mocks.json\"}}".getBytes(StandardCharsets.UTF_8)));
        when(downloadUrlGenerator.preSignUrl(eq("mocks3path/mocks.json"))).thenReturn(new URL("http://www.someawsurl.com/mocks3path/mocks.json"));

        when(metadataStreamProvider.download(eq("arraymocks/metadata.json"))).thenReturn(new ByteArrayInputStream("{\"arraymocks\":[{\"location\":\"mocks3path/arraymocks.json\"}]}".getBytes(StandardCharsets.UTF_8)));
        when(downloadUrlGenerator.preSignUrl(eq("mocks3path/arraymocks.json"))).thenReturn(new URL("http://www.someawsurl.com/mocks3path/arraymocks.json"));

        metadataProvider = new MockMetadataProvider(metadataStreamProvider, downloadUrlGenerator);
    }

    @Test
    public void testGetMetadata() throws Exception {
        String metadata = metadataProvider.getMetadata();
        assertEquals("{\"mocks\":{\"location\":\"http://www.someawsurl.com/mocks3path/mocks.json\"}}", metadata);
    }

    @Test
    public void testGetMetadataWithOperatorInfo() throws Exception {
        String metadata = metadataProvider.getMetadata(new OperatorInfo(OperatorType.PUBLIC, 0, false));
        assertEquals("{\"mocks\":{\"location\":\"http://www.someawsurl.com/mocks3path/mocks.json\"}}", metadata);
    }

    @Test
    public void testGetArrayMetadata() throws Exception {
        String metadata = metadataProvider.getArrayMetadata(new OperatorInfo(OperatorType.PUBLIC, 0, false));
        assertEquals("{\"arraymocks\":[{\"location\":\"http://www.someawsurl.com/mocks3path/arraymocks.json\"}]}", metadata);
    }

    @Test
    public void testGetGlobalScopeMetadata() throws Exception {
        String metadata = metadataProvider.getGlobalMetadata();
        assertEquals("{\"mocks\":{\"location\":\"http://www.someawsurl.com/mocks3path/mocks.json\"}}", metadata);
    }

    private static class MockMetadataProvider extends MetadataProvider {
        public MockMetadataProvider(ICloudStorage cloudStorage) {
            super(cloudStorage);
        }

        public MockMetadataProvider(ICloudStorage fileStreamProvider, ICloudStorage downloadUrlGenerator) {
            super(fileStreamProvider, downloadUrlGenerator);
        }

        public String getMetadata() throws Exception {
            return getMetadata("mocks_metadata_path", "mocks");
        }

        public String getMetadata(OperatorInfo info) throws Exception {
            return getMetadata(info, "mocks_metadata_path", "mocks");
        }

        public String getArrayMetadata(OperatorInfo info) throws Exception {
            return getArrayMetadata(info, "arraymocks_metadata_path", "arraymocks");
        }

        public String getGlobalMetadata() throws Exception {
            return getGlobalScopeMetadata("mocks_metadata_path", "mocks");
        }
    }
}
