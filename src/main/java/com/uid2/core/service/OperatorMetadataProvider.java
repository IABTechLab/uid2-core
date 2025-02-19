package com.uid2.core.service;

import com.uid2.shared.cloud.ICloudStorage;

public class OperatorMetadataProvider extends MetadataProvider {
    public OperatorMetadataProvider(ICloudStorage cloudStorage) {
        super(cloudStorage);
    }

    public OperatorMetadataProvider(ICloudStorage fileStreamProvider, ICloudStorage downloadUrlGenerator) {
        super(fileStreamProvider, downloadUrlGenerator);
    }

    public String getMetadata() throws Exception {
        return getMetadata("operators_metadata_path", "operators");
    }
}
