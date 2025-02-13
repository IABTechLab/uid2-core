package com.uid2.core.service;

import com.uid2.shared.cloud.ICloudStorage;

public class PartnerMetadataProvider extends MetadataProvider {
    public static final String PartnersMetadataPathName = "partners_metadata_path";

    public PartnerMetadataProvider(ICloudStorage cloudStorage) {
        super(cloudStorage);
    }

    public PartnerMetadataProvider(ICloudStorage fileStreamProvider, ICloudStorage downloadUrlGenerator) {
        super(fileStreamProvider, downloadUrlGenerator);
    }

    public String getMetadata() throws Exception {
        return getMetadata(PartnersMetadataPathName, "partners");
    }
}
