package com.uid2.core.service;

import com.uid2.core.model.SecretStore;
import com.uid2.core.util.OperatorInfo;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.scope.GlobalScope;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import lombok.Getter;

import static com.uid2.core.util.MetadataHelper.*;

@Getter
public abstract class MetadataProvider {
    private final ICloudStorage metadataStreamProvider;
    private final ICloudStorage downloadUrlGenerator;

    protected MetadataProvider(ICloudStorage cloudStorage) {
        this.metadataStreamProvider = this.downloadUrlGenerator = cloudStorage;
    }

    protected MetadataProvider(ICloudStorage fileStreamProvider, ICloudStorage downloadUrlGenerator) {
        this.metadataStreamProvider = fileStreamProvider;
        this.downloadUrlGenerator = downloadUrlGenerator;
    }

    protected String getMetadata(String metadataPath, String keyName) throws Exception {
        String json = readToEndAsString(metadataStreamProvider.download(SecretStore.Global.get(metadataPath)));
        return getMetadataJson(json, keyName);
    }

    protected String getMetadata(OperatorInfo info, String metadataPath, String keyName) throws Exception {
        String pathName = getMetadataPathName(info, SecretStore.Global.get(metadataPath));
        String json = readToEndAsString(metadataStreamProvider.download(pathName));
        return getMetadataJson(json, keyName);
    }

    protected String getArrayMetadata(OperatorInfo info, String metadataPath, String keyName) throws Exception {
        String pathname = getMetadataPathNameOldPrivateNoSite(info, SecretStore.Global.get(metadataPath));
        String original = readToEndAsString(metadataStreamProvider.download(pathname));
        JsonObject main = (JsonObject) Json.decodeValue(original);
        JsonArray arr = main.getJsonArray(keyName);
        for(int i = 0; i < arr.size(); ++i) {
            JsonObject obj = arr.getJsonObject(i);
            String location = obj.getString("location");
            obj.put("location", downloadUrlGenerator.preSignUrl(location).toString());
        }
        return main.encode();
    }

    protected String getGlobalScopeMetadata(String metadataPath, String keyName) throws Exception {
        String pathName = new GlobalScope(new CloudPath(SecretStore.Global.get(metadataPath))).getMetadataPath().toString();
        String json = readToEndAsString(metadataStreamProvider.download(pathName));
        return getMetadataJson(json, keyName);
    }

    private String getMetadataJson(String json, String keyName) throws Exception {
        JsonObject main = (JsonObject) Json.decodeValue(json);
        JsonObject obj = main.getJsonObject(keyName);
        String location = obj.getString("location");
        obj.put("location", downloadUrlGenerator.preSignUrl(location).toString());
        return main.encode();
    }
}
