package com.uid2.core.service;

import com.uid2.core.util.OperatorInfo;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.Const;

public class KeysetMetadataProvider extends MetadataProvider {
    public KeysetMetadataProvider(ICloudStorage cloudStorage) {
        super(cloudStorage);
    }

    public KeysetMetadataProvider(ICloudStorage fileStreamProvider, ICloudStorage downloadUrlGenerator) {
        super(fileStreamProvider, downloadUrlGenerator);
    }

    public String getMetadata(OperatorInfo info) throws Exception {
        return getMetadata(info, Const.Config.KeysetsMetadataPathProp, "keysets");
    }
}
