package com.uid2.core.service;

import com.uid2.shared.cloud.ICloudStorage;

public class ServiceLinkMetadataProvider extends MetadataProvider {
    public ServiceLinkMetadataProvider(ICloudStorage cloudStorage) {
        super(cloudStorage);
    }

    public ServiceLinkMetadataProvider(ICloudStorage fileStreamProvider, ICloudStorage downloadUrlGenerator) {
        super(fileStreamProvider, downloadUrlGenerator);
    }

    public String getMetadata() throws Exception {
        return getGlobalScopeMetadata("service_links_metadata_path", "service_links");
    }
}
