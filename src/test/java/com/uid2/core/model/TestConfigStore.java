package com.uid2.core.model;

import com.uid2.core.vertx.TestSiteSpecificMetadataPathDisabled;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static com.uid2.shared.Utils.readToEndAsString;
import static org.junit.jupiter.api.Assertions.*;

public class TestConfigStore {
    @Test
    void loadIntegerSuccess() throws IOException {
        ConfigStore store = new ConfigStore();
        store.load(((JsonObject) Json.decodeValue(openFile("/com.uid2.core/model/test-config.json"))));
        Integer token_lifespan = store.getInteger("att_token_lifetime_seconds");

        assertEquals(120, token_lifespan);
    }

    @Test
    void loadMissingIntegerReturnsNull() throws IOException {
        ConfigStore store = new ConfigStore();
        store.load(((JsonObject) Json.decodeValue(openFile("/com.uid2.core/model/test-config.json"))));
        Integer t = store.getInteger("missing_key");

        assertNull(t);
    }

    @Test
    void loadIntegerDefaultForMissingKeySuccess() throws IOException {
        ConfigStore store = new ConfigStore();
        store.load(((JsonObject) Json.decodeValue(openFile("/com.uid2.core/model/test-config.json"))));
        Integer token_lifespan = store.getIntegerOrDefault("missing_key", 45);

        assertEquals(45, token_lifespan);
    }

    @Test
    void loadIntegerDefaultForKnownKeySuccess() throws IOException {
        ConfigStore store = new ConfigStore();
        store.load(((JsonObject) Json.decodeValue(openFile("/com.uid2.core/model/test-config.json"))));
        Integer token_lifespan = store.getIntegerOrDefault("att_token_lifetime_seconds", 120);

        assertEquals(120, token_lifespan);
    }

    String openFile(String filePath) throws IOException {
        return readToEndAsString(TestSiteSpecificMetadataPathDisabled.class.getResourceAsStream(filePath));
    }
}
