package com.uid2.core.model;

import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class ConfigStore {

    public static final ConfigStore Global = new ConfigStore();

    private static final Logger logger = LoggerFactory.getLogger(ConfigStore.class);

    private Map<String, Object> secrets = new HashMap<>();

    public String get(String key) {
        return (String)secrets.get(key);
    }

    public Boolean getBoolean(String key) {
        try {
            return (Boolean) secrets.get(key);
        } catch (NullPointerException e) {
            return null;
        }
    }

    public Integer getInteger(String key) {
        try {
            return (Integer) secrets.get(key);
        } catch (NullPointerException e) {
            return null;
        }
    }

    public long getLongOrDefault(String key, long defaultValue) {
        try {
            return ((Long) secrets.get(key)).longValue();
        } catch (NullPointerException e) {
            return defaultValue;
        }
    }

    public String getPrintable(String key) { return get(key); }

    public String getOrDefault(String key, String defaultValue) {
        return (String) secrets.getOrDefault(key, defaultValue);
    }

    public void load(String configFilePath) throws IOException {
        logger.info("loading " + this.getClass().getName() + " from " + configFilePath);
        InputStream stream = new FileInputStream(configFilePath);
        JsonObject configJson = (JsonObject) Json.decodeValue(readToEndAsString(stream));
        deserialize(configJson);
    }

    public void load(JsonObject config) {
        logger.info("loading " + this.getClass().getName() + " from JsonObject");
        deserialize(config);
    }

    private void deserialize(JsonObject config) {
        HashMap<String, Object> dst = new HashMap<>();
        config.getMap().forEach((k, v) -> dst.put(k, v));
        secrets = Collections.unmodifiableMap(dst);
    }

    private static String readToEndAsString(InputStream stream) throws IOException {
        final InputStreamReader reader = new InputStreamReader(stream);
        final char[] buff = new char[1024];
        final StringBuilder sb = new StringBuilder();
        for (int count; (count = reader.read(buff, 0, buff.length)) > 0;) {
            sb.append(buff, 0, count);
        }
        return sb.toString();
    }
}
