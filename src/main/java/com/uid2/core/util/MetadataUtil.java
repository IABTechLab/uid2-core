package com.uid2.core.util;

import com.uid2.core.model.ConfigStore;
import com.uid2.shared.auth.OperatorType;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.scope.GlobalScope;
import com.uid2.shared.store.scope.SiteScope;
import com.uid2.shared.store.scope.StoreScope;

public final class MetadataUtil {
    private MetadataUtil() {
    }

    // Can make this as a config in admin/core service config
    private static final String SITE_SPECIFIC_DATA_SUB_DIR_PATH = "sites/";

    public static String getSiteSpecificMetadataPathName(int siteId, String metadataPathName) {
        return SITE_SPECIFIC_DATA_SUB_DIR_PATH + siteId + metadataPathName;
    }

    public static String getMetadataPathName(OperatorType operatorType, int siteId, String metadataPathName)
    {
        StoreScope store;
        Boolean providePrivateSiteData = ConfigStore.GLOBAL.getBoolean("provide_private_site_data");
        if (operatorType == OperatorType.PUBLIC || (providePrivateSiteData == null || !providePrivateSiteData)) {
            store = new GlobalScope(new CloudPath(metadataPathName));
        } else { // PRIVATE
            store = new SiteScope(new CloudPath(metadataPathName), siteId);
        }
        return store.getMetadataPath().toString();
    }
}