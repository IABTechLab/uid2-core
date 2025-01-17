package com.uid2.core.service;

import com.uid2.core.util.OperatorInfo;
import com.uid2.shared.Const;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.core.model.SecretStore;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;


import static com.uid2.core.util.MetadataHelper.getMetadataPathName;
import static com.uid2.core.util.MetadataHelper.readToEndAsString;

public class KeysetKeysMetadataProvider implements IKeysetKeyMetadataProvider {
    private final ICloudStorage metadataStreamProvider;
    private final ICloudStorage downloadUrlGenerator;

    public KeysetKeysMetadataProvider(ICloudStorage cloudStorage) {
        this.metadataStreamProvider = this.downloadUrlGenerator = cloudStorage;
    }

    @Override
    public String getMetadata(OperatorInfo info) throws Exception {
        String pathname = getMetadataPathName(info, SecretStore.Global.get(Const.Config.KeysetKeysMetadataPathProp));
        String original = readToEndAsString(metadataStreamProvider.download(pathname));
        JsonObject main = (JsonObject) Json.decodeValue(original);
        JsonObject obj = main.getJsonObject("keyset_keys");
        String location = obj.getString("location");
        obj.put("location", downloadUrlGenerator.preSignUrl(location).toString());
        return main.encode();
    }
}
