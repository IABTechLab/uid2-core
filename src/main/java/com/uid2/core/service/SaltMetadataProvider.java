package com.uid2.core.service;

import com.uid2.core.util.OperatorInfo;
import com.uid2.shared.cloud.ICloudStorage;

public class SaltMetadataProvider extends MetadataProvider {
    public SaltMetadataProvider(ICloudStorage cloudStorage) {
        super(cloudStorage);
    }

    public SaltMetadataProvider(ICloudStorage fileStreamProvider, ICloudStorage downloadUrlGenerator) {
        super(fileStreamProvider, downloadUrlGenerator);
    }

    public String getMetadata(OperatorInfo info) throws Exception {
        return getArrayMetadata(info, "salts_metadata_path", "salts");
    }
}
