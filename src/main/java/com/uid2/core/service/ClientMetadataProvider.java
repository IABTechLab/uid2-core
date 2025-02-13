package com.uid2.core.service;

import com.uid2.core.util.OperatorInfo;
import com.uid2.shared.cloud.ICloudStorage;

public class ClientMetadataProvider extends MetadataProvider {
    public static final String ClientsMetadataPathName = "clients_metadata_path";

    public ClientMetadataProvider(ICloudStorage cloudStorage) {
        super(cloudStorage);
    }

    public ClientMetadataProvider(ICloudStorage fileStreamProvider, ICloudStorage downloadUrlGenerator) {
        super(fileStreamProvider, downloadUrlGenerator);
    }

    public String getMetadata(OperatorInfo info) throws Exception {
        return getMetadata(info, ClientsMetadataPathName, "client_keys");
    }
}
