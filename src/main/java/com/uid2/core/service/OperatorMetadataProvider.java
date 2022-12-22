package com.uid2.core.service;

import com.uid2.core.model.SecretStore;
import com.uid2.shared.cloud.ICloudStorage;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import static com.uid2.shared.Utils.getMetadataPathName;

public class OperatorMetadataProvider implements IOperatorMetadataProvider {

    public static final String OperatorsMetadataPathName = "operators_metadata_path";

    private final ICloudStorage metadataStreamProvider;
    private final ICloudStorage downloadUrlGenerator;

    @Override
    public String getMetadata(boolean isPublicOperator, int siteId) throws Exception {
        String pathname = getMetadataPathName(isPublicOperator, siteId, SecretStore.Global.get(OperatorsMetadataPathName));
        String original = readToEndAsString(metadataStreamProvider.download(pathname));
        JsonObject main = (JsonObject) Json.decodeValue(original);
        JsonObject obj = main.getJsonObject("operators");
        String location = obj.getString("location");
        obj.put("location", downloadUrlGenerator.preSignUrl(location).toString());
        return main.encode();
    }

    public OperatorMetadataProvider(ICloudStorage cloudStorage) {
        this.metadataStreamProvider = this.downloadUrlGenerator = cloudStorage;
    }

    public OperatorMetadataProvider(ICloudStorage fileStreamProvider, ICloudStorage downloadUrlGenerator) {
        this.metadataStreamProvider = fileStreamProvider;
        this.downloadUrlGenerator = downloadUrlGenerator;
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
