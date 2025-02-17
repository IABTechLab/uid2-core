package com.uid2.core.service;

import com.uid2.core.model.SecretStore;
import com.uid2.core.util.OperatorInfo;
import com.uid2.shared.cloud.ICloudStorage;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static com.uid2.core.util.MetadataHelper.*;

public class SaltMetadataProvider extends MetadataProvider {
    public SaltMetadataProvider(ICloudStorage cloudStorage) {
        super(cloudStorage);
    }

    public SaltMetadataProvider(ICloudStorage fileStreamProvider, ICloudStorage downloadUrlGenerator) {
        super(fileStreamProvider, downloadUrlGenerator);
    }

    public String getMetadata(OperatorInfo info) throws Exception {
        String pathname = getMetadataPathNameOldPrivateNoSite(info, SecretStore.Global.get("salts_metadata_path"));
        String original = readToEndAsString(getMetadataStreamProvider().download(pathname));
        JsonObject main = (JsonObject) Json.decodeValue(original);
        JsonArray salts = main.getJsonArray("salts");
        for(JsonObject obj : salts) {
            String location = obj.getString("location");
            obj.put("location", downloadUrlGenerator.preSignUrl(location).toString());
        }
        return main.encode();
    }
}
