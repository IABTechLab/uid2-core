package com.uid2.core.service;

public interface IKeyMetadataProvider {
    String getMetadata(boolean isPublicOperator, int siteId) throws Exception;
}
