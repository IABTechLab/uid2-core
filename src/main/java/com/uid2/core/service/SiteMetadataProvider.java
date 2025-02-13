package com.uid2.core.service;

import com.uid2.core.util.OperatorInfo;
import com.uid2.shared.cloud.ICloudStorage;

public class SiteMetadataProvider extends MetadataProvider {
    public static final String SiteMetadataPathName = "sites_metadata_path";

    public SiteMetadataProvider(ICloudStorage cloudStorage) {
        super(cloudStorage);
    }

    public SiteMetadataProvider(ICloudStorage fileStreamProvider, ICloudStorage downloadUrlGenerator) {
        super(fileStreamProvider, downloadUrlGenerator);
    }

    public String getMetadata(OperatorInfo info) throws Exception {
        return getMetadata(info, SiteMetadataPathName, "sites");
    }
}
