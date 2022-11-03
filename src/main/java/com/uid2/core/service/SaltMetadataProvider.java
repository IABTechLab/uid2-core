package com.uid2.core.service;

import com.uid2.core.model.SecretStore;
import com.uid2.shared.cloud.ICloudStorage;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class SaltMetadataProvider implements ISaltMetadataProvider {

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
    public String getMetadata() throws Exception {
        String original = readToEndAsString(metadataStreamProvider.download(SecretStore.Global.get(SaltsMetadataPathName)));
        JsonObject main = (JsonObject) Json.decodeValue(original);
        JsonArray salts = main.getJsonArray("salts");
        for(int i=0;i<salts.size();++i) {
            JsonObject obj = salts.getJsonObject(i);
            String location = obj.getString("location");
            obj.put("location", downloadUrlGenerator.preSignUrl(location).toString());
        }
        return main.encode();
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
