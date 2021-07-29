// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package com.uid2.core.model;

import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;

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
