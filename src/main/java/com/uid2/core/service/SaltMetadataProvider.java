package com.uid2.core.service;

import com.uid2.core.model.SecretStore;
import com.uid2.core.util.OperatorInfo;
import com.uid2.shared.cloud.ICloudStorage;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import static com.uid2.core.util.MetadataHelper.*;

public class SaltMetadataProvider implements ISaltMetadataProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(SaltMetadataProvider.class);

    public static final String SaltsMetadataPathName = "salts_metadata_path";

    private final ICloudStorage metadataStreamProvider;
    private final ICloudStorage downloadUrlGenerator;

    public SaltMetadataProvider(ICloudStorage cloudStorage) {
        this.metadataStreamProvider = this.downloadUrlGenerator = cloudStorage;
    }

    public SaltMetadataProvider(ICloudStorage fileStreamProvider, ICloudStorage downloadUrlGenerator) {
        this.metadataStreamProvider = fileStreamProvider;
        this.downloadUrlGenerator = downloadUrlGenerator;
    }

    @Override
    public String getMetadata(OperatorInfo info) throws Exception {
        String pathname = getMetadataPathNameOldPrivateNoSite(info, SecretStore.Global.get(SaltsMetadataPathName));
        String original = readToEndAsString(metadataStreamProvider.download(pathname));
        JsonObject main = (JsonObject) Json.decodeValue(original);
        JsonArray salts = main.getJsonArray("salts");
        for(int i=0;i<salts.size();++i) {
            JsonObject obj = salts.getJsonObject(i);
            String location = obj.getString("location");
            obj.put("location", downloadUrlGenerator.preSignUrl(location).toString());
        }
        return main.encode();
    }
}
