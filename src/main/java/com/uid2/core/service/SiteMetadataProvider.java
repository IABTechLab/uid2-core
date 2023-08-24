package com.uid2.core.service;

import com.uid2.core.model.SecretStore;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.scope.GlobalScope;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import static com.uid2.core.util.MetadataHelper.readToEndAsString;

public class SiteMetadataProvider implements ISiteMetadataProvider {
    public static final String SiteMetadataPathName = "sites_metadata_path";
    private final ICloudStorage metadataStreamProvider;
    private final ICloudStorage downloadUrlGenerator;

    public SiteMetadataProvider(ICloudStorage cloudStorage) {
        this.metadataStreamProvider = this.downloadUrlGenerator = cloudStorage;
    }
    @Override
    public String getMetadata() throws Exception {
        String pathname = new GlobalScope(new CloudPath(SecretStore.Global.get(SiteMetadataPathName))).getMetadataPath().toString();
        String original = readToEndAsString(metadataStreamProvider.download(pathname));
        JsonObject main = (JsonObject) Json.decodeValue(original);
        JsonObject obj = main.getJsonObject("sites");
        String location = obj.getString("location");
        obj.put("location", downloadUrlGenerator.preSignUrl(location).toString());
        return main.encode();
    }
}
