package com.uid2.core.util;

import com.uid2.core.model.ConfigStore;
import com.uid2.shared.auth.OperatorType;
import com.uid2.shared.auth.Role;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.scope.EncryptedScope;
import com.uid2.shared.store.scope.GlobalScope;
import com.uid2.shared.store.scope.SiteScope;
import com.uid2.shared.store.scope.StoreScope;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Optional;

public final class MetadataHelper {

    //can make this as an config in admin/core service config
    public static final String SiteSpecificDataSubDirPath = "sites/";
    public static String getSiteSpecificMetadataPathName(int siteId, String metadataPathName)
    {
        return SiteSpecificDataSubDirPath +siteId + metadataPathName;
    }

    public static String getMetadataPathName(OperatorType operatorType, int siteId, String metadataPathName)
    {
        StoreScope store;
        Boolean providePrivateSiteData = ConfigStore.Global.getBoolean("provide_private_site_data");
        // need a logic to know if operator can decrypt stuff or not
        Boolean canDecrypt = false;
        if (canDecrypt){
            if (operatorType == OperatorType.PUBLIC){
                store = new EncryptedScope(new CloudPath(metadataPathName),siteId, true);
            }else{
                store = new EncryptedScope(new CloudPath(metadataPathName),siteId, false);
            }
        }else{
            if (operatorType == OperatorType.PUBLIC || (providePrivateSiteData == null || !providePrivateSiteData.booleanValue()))
            {
                store = new GlobalScope(new CloudPath(metadataPathName));
            }
            else //PRIVATE
            {
                store = new SiteScope(new CloudPath(metadataPathName), siteId);
            }
        }
        return store.getMetadataPath().toString();
    }

    public static String readToEndAsString(InputStream stream) throws IOException {
        final InputStreamReader reader = new InputStreamReader(stream);
        final char[] buff = new char[1024];
        final StringBuilder sb = new StringBuilder();
        for (int count; (count = reader.read(buff, 0, buff.length)) > 0;) {
            sb.append(buff, 0, count);
        }
        return sb.toString();
    }
}
