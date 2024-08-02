package com.uid2.core.util;
import com.uid2.shared.auth.IAuthorizable;
import com.uid2.shared.auth.OperatorKey;
import com.uid2.shared.auth.OperatorType;
import io.vertx.ext.web.RoutingContext;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.uid2.core.model.ConfigStore;

import static com.uid2.shared.middleware.AuthMiddleware.API_CLIENT_PROP;

/**
 * Given a logged in operator, determine its site id and if it's a public/private
 * Typically this should be extracting these details from the according OperatorKey
 */
public class OperatorInfo {
    private final OperatorType operatorType;
    private final int siteId;
    private final boolean supportsEncryption;
    private static final String ENCRYPTION_SUPPORT_VERSION = ConfigStore.Global.get("encryption_support_version");

    public OperatorType getOperatorType() {
        return operatorType;
    }

    public int getSiteId() {
        return siteId;
    }

    public boolean getSupportsEncryption() {return supportsEncryption;}

    public OperatorInfo(OperatorType operatorType, int siteId, boolean supportsEncryption) {
        this.operatorType = operatorType;
        this.siteId = siteId;
        this.supportsEncryption = supportsEncryption;
    }

    public static OperatorInfo getOperatorInfo(RoutingContext rc) throws Exception {
        IAuthorizable profile = (IAuthorizable) rc.data().get(API_CLIENT_PROP);
        if (profile instanceof OperatorKey) {
            OperatorKey operatorKey = (OperatorKey) profile;
            boolean supportsEncryption = supportsEncryption(rc);
            return new OperatorInfo(operatorKey.getOperatorType(), operatorKey.getSiteId(), supportsEncryption);
        }
        throw new Exception("Cannot determine the operator type and site id from the profile");
    }

    private static boolean supportsEncryption(RoutingContext rc) {
        String appVersion = rc.request().getHeader("AppVersion");
        if (appVersion == null) return false;
        String[] versions = appVersion.split(";");
        for (String version : versions) {
            if (version.startsWith("uid2-operator=")) {
                String operatorVersion = version.substring("uid2-operator=".length());
                return isVersionGreaterOrEqual(operatorVersion, ENCRYPTION_SUPPORT_VERSION);
            }
        }
        return false;
    }

    private static boolean isVersionGreaterOrEqual(String v1, String v2) {
        Pattern pattern = Pattern.compile("(\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?");
        Matcher m1 = pattern.matcher(v1);
        Matcher m2 = pattern.matcher(v2);

        int[] parts1 = extractParts(m1);
        int[] parts2 = extractParts(m2);

        for (int i = 0; i < Math.max(parts1.length, parts2.length); i++) {
            int p1 = i < parts1.length ? parts1[i] : 0;
            int p2 = i < parts2.length ? parts2[i] : 0;
            if (p1 != p2) {
                return p1 > p2;
            }
        }

        return true;
    }

    private static int[] extractParts(Matcher matcher) {
        int[] parts = new int[3];
        if (matcher.find()) {
            for (int i = 1; i <= 3; i++) {
                String group = matcher.group(i);
                parts[i - 1] = group != null ? Integer.parseInt(group) : 0;
            }
        }
        return parts;
    }
}