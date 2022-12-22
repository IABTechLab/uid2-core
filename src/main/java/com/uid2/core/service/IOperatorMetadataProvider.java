package com.uid2.core.service;

public interface IOperatorMetadataProvider {
    String getMetadata(boolean isPublicOperator, int siteId) throws Exception;
}
