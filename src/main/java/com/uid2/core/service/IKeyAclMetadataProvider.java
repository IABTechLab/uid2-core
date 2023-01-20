package com.uid2.core.service;

import com.uid2.core.util.OperatorInfo;
import com.uid2.shared.auth.OperatorType;

public interface IKeyAclMetadataProvider {
    String getMetadata(OperatorInfo info) throws Exception;
}
