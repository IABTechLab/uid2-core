package com.uid2.core.service;

import com.uid2.core.util.OperatorInfo;

public interface IKeyAclMetadataProvider {
    String getMetadata(OperatorInfo info) throws Exception;
    String getEncryptedMetadata(OperatorInfo info) throws Exception;
}
