package com.uid2.core.service;

import com.uid2.core.util.OperatorInfo;
import com.uid2.shared.cloud.ICloudStorage;

public class KeyMetadataProvider extends MetadataProvider {
    public KeyMetadataProvider(ICloudStorage cloudStorage) {
        super(cloudStorage);
    }

    public KeyMetadataProvider(ICloudStorage fileStreamProvider, ICloudStorage downloadUrlGenerator) {
        super(fileStreamProvider, downloadUrlGenerator);
    }

    public String getMetadata(OperatorInfo info) throws Exception {
        return getMetadata(info, "keys_metadata_path", "keys");
    }
}
