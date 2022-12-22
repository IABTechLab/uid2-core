package com.uid2.core.service;

public interface IKeyAclMetadataProvider {
    String getMetadata(boolean isPublicOperator, int siteId) throws Exception;
}
