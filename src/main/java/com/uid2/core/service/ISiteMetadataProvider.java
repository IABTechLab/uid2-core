package com.uid2.core.service;

import com.uid2.core.util.OperatorInfo;

public interface ISiteMetadataProvider {
    String getMetadata(OperatorInfo info) throws Exception;
}
