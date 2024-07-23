package com.uid2.core.service;

import com.uid2.core.model.SecretStore;
import com.uid2.core.util.OperatorInfo;
import com.uid2.shared.Const;
import com.uid2.shared.cloud.ICloudStorage;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;

import static com.uid2.core.util.MetadataHelper.*;

public class KeyAclMetadataProvider implements IKeyAclMetadataProvider {

    private final ICloudStorage metadataStreamProvider;
    private final ICloudStorage downloadUrlGenerator;

    public KeyAclMetadataProvider(ICloudStorage cloudStorage) {
        this.metadataStreamProvider = this.downloadUrlGenerator = cloudStorage;
    }

    @Override
    public String getMetadata(OperatorInfo info) throws Exception {
        String pathname = getMetadataPathName(info.getOperatorType(), info.getSiteId(), SecretStore.Global.get(Const.Config.KeysAclMetadataPathProp));
        String original = readToEndAsString(metadataStreamProvider.download(pathname));
        JsonObject main = (JsonObject) Json.decodeValue(original);
        JsonObject obj = main.getJsonObject("keys_acl");
        String location = obj.getString("location");
        obj.put("location", downloadUrlGenerator.preSignUrl(location).toString());
        return main.encode();
    }

    public String getEncryptedMetadata(OperatorInfo info) throws Exception {
        String pathname = getEncryptedMetadataPathName(info.getOperatorType(), info.getSiteId(), SecretStore.Global.get(Const.Config.KeysAclMetadataPathProp));
        String original = readToEndAsString(metadataStreamProvider.download(pathname));
        JsonObject main = (JsonObject) Json.decodeValue(original);
        JsonObject obj = main.getJsonObject("keys_acl");
        String location = obj.getString("location");
        obj.put("location", downloadUrlGenerator.preSignUrl(location).toString());
        return main.encode();
    }

}
