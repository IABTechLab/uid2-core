package com.uid2.core.service;

public interface IClientMetadataProvider {
    String getMetadata(boolean isPublicOperator, int siteId) throws Exception;
}
