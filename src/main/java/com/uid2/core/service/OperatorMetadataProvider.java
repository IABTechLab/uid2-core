package com.uid2.core.service;

import com.uid2.core.model.SecretStore;
import com.uid2.shared.cloud.ICloudStorage;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import static com.uid2.core.util.MetadataHelper.readToEndAsString;

public class OperatorMetadataProvider implements IOperatorMetadataProvider {

    public static final String OperatorsMetadataPathName = "operators_metadata_path";

    private final ICloudStorage metadataStreamProvider;
    private final ICloudStorage downloadUrlGenerator;

    @Override
    public String getMetadata() throws Exception {
        String original = readToEndAsString(metadataStreamProvider.download(SecretStore.Global.get(OperatorsMetadataPathName)));
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

}
