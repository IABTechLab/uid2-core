package com.uid2.core.service;

import com.uid2.core.util.OperatorInfo;
import com.uid2.shared.cloud.ICloudStorage;

public class ClientSideKeypairMetadataProvider extends MetadataProvider {
    public static final String ClientSideKeypairMetadataPathName = "client_side_keypairs_metadata_path";

    public ClientSideKeypairMetadataProvider(ICloudStorage cloudStorage) {
        super(cloudStorage);
    }

    public ClientSideKeypairMetadataProvider(ICloudStorage fileStreamProvider, ICloudStorage downloadUrlGenerator) {
        super(fileStreamProvider, downloadUrlGenerator);
    }

    public String getMetadata(OperatorInfo info) throws Exception {
        return getMetadata(info, ClientSideKeypairMetadataPathName, "client_side_keypairs");
    }
}
