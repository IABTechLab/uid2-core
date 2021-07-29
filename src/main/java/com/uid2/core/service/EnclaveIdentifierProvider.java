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

package com.uid2.core.service;

import com.uid2.core.model.EnclaveIdentifier;
import com.uid2.shared.Utils;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.store.IMetadataVersionedStore;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;

import java.io.InputStream;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

public class EnclaveIdentifierProvider implements IEnclaveIdentifierProvider, IMetadataVersionedStore {

    public static final String ENCLAVES_METADATA_PATH = "enclaves_metadata_path";

    private static final Logger LOGGER = LoggerFactory.getLogger(EnclaveIdentifierProvider.class);

    private final ICloudStorage metadataStreamProvider;
    private final ICloudStorage contentStreamProvider;
    private final String metadataPath;
    private final AtomicReference<Set<EnclaveIdentifier>> snapshot;
    private final List<IOperatorChangeHandler> changeEventListeners = new ArrayList<>();

    public EnclaveIdentifierProvider(ICloudStorage fileStreamProvider, String metadataPath) {
        this.metadataStreamProvider = this.contentStreamProvider = fileStreamProvider;
        this.metadataPath = metadataPath;
        this.snapshot = new AtomicReference<>(new HashSet<>());
    }

    @Override
    public void addListener(IOperatorChangeHandler handler) throws IllegalArgumentException {
        if(handler == null) {
            throw new IllegalArgumentException("handler cannot be null");
        }
        if(!changeEventListeners.contains(handler)) {
            changeEventListeners.add(handler);
            handler.handle(snapshot.get());
        }
    }

    @Override
    public void removeListener(IOperatorChangeHandler handler) {
        if(changeEventListeners.contains(handler)) {
            changeEventListeners.remove(handler);
        }
    }

    @Override
    public JsonObject getMetadata() throws Exception {
        InputStream s = this.metadataStreamProvider.download(this.metadataPath);
        return Utils.toJsonObject(s);
    }

    @Override
    public long getVersion(JsonObject metadata) {
        return metadata.getLong("version");
    }

    @Override
    public long loadContent(JsonObject metadata) throws Exception {
        JsonObject root = metadata.getJsonObject("enclaves");
        String path = root.getString("location");
        InputStream in = this.contentStreamProvider.download(path);
        JsonArray idList = Utils.toJsonArray(in);
        Set<EnclaveIdentifier> newSet = new HashSet<>();
        for (int i = 0; i < idList.size(); i++) {
            JsonObject item = idList.getJsonObject(i);
            EnclaveIdentifier id = new EnclaveIdentifier(
                item.getString("name"),
                item.getString("protocol"),
                item.getString("identifier"),
                item.getLong("created"));
            newSet.add(id);
        }

        LOGGER.info("Loaded " + newSet.size() + " enclave profiles");

        snapshot.set(newSet);
        for(IOperatorChangeHandler handler : changeEventListeners) {
            handler.handle(newSet);
        }

        return newSet.size();
    }

    @Override
    public Collection<EnclaveIdentifier> getAll() {
        return snapshot.get();
    }

    public String getMetadataPath() {
        return metadataPath;
    }
}
