package com.uid2.core.service;

import com.uid2.core.model.SecretStore;
import com.uid2.core.util.OperatorInfo;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.scope.GlobalScope;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import static com.uid2.core.util.MetadataHelper.getMetadataPathName;
import static com.uid2.core.util.MetadataHelper.readToEndAsString;

public class ClientSideKeypairMetadataProvider implements IClientSideKeypairMetadataProvider {
    public static final String ClientSideKeypairMetadataPathName = "client_side_keypairs_metadata_path";

    private final ICloudStorage metadataStreamProvider;
    private final ICloudStorage downloadUrlGenerator;

    public ClientSideKeypairMetadataProvider(ICloudStorage cloudStorage) {
        this.metadataStreamProvider = this.downloadUrlGenerator = cloudStorage;
    }

    @Override
    public String getMetadata(OperatorInfo info) throws Exception {
        String pathname = getMetadataPathName(info, SecretStore.Global.get(ClientSideKeypairMetadataPathName));
        String original = readToEndAsString(metadataStreamProvider.download(pathname));
        JsonObject main = (JsonObject) Json.decodeValue(original);
        JsonObject obj = main.getJsonObject("client_side_keypairs");
        String location = obj.getString("location");
        obj.put("location", downloadUrlGenerator.preSignUrl(location).toString());
        return main.encode();
    }
}
