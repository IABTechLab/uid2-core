package com.uid2.core.service;

import com.uid2.shared.cloud.ICloudStorage;

public class ServiceMetadataProvider extends MetadataProvider {
    public ServiceMetadataProvider(ICloudStorage cloudStorage) {
        super(cloudStorage);
    }

    public ServiceMetadataProvider(ICloudStorage fileStreamProvider, ICloudStorage downloadUrlGenerator) {
        super(fileStreamProvider, downloadUrlGenerator);
    }

    public String getMetadata() throws Exception {
        return getGlobalScopeMetadata("services_metadata_path", "services");
    }
}
