package com.uid2.core.service;

import com.uid2.core.util.OperatorInfo;

public interface IKeysetKeyMetadataProvider {
    String getMetadata(OperatorInfo info) throws Exception;
}
