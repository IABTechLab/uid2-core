package com.uid2.core.service;

import com.uid2.core.util.OperatorInfo;
import com.uid2.shared.Const;
import com.uid2.shared.cloud.ICloudStorage;

public class KeyAclMetadataProvider extends MetadataProvider {
    public KeyAclMetadataProvider(ICloudStorage cloudStorage) {
        super(cloudStorage);
    }

    public KeyAclMetadataProvider(ICloudStorage fileStreamProvider, ICloudStorage downloadUrlGenerator) {
        super(fileStreamProvider, downloadUrlGenerator);
    }

    public String getMetadata(OperatorInfo info) throws Exception {
        return getMetadata(info, Const.Config.KeysAclMetadataPathProp, "keys_acl");
    }
}
