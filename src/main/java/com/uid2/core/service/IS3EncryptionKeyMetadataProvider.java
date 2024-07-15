package com.uid2.core.service;
import com.uid2.core.util.OperatorInfo;

public interface IS3EncryptionKeyMetadataProvider {
    String getMetadata(OperatorInfo info) throws Exception;
}
