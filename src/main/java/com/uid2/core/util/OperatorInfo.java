package com.uid2.core.util;
import com.uid2.core.Const;
import com.uid2.shared.auth.IAuthorizable;
import com.uid2.shared.auth.OperatorKey;
import com.uid2.shared.auth.OperatorType;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.uid2.core.model.ConfigStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.uid2.shared.Const.Config.encryptionSupportVersion;
import static com.uid2.shared.Const.Http.AppVersionHeader;
import static com.uid2.shared.middleware.AuthMiddleware.API_CLIENT_PROP;

/**
 * Given a logged in operator, determine its site id and if it's a public/private
 * Typically this should be extracting these details from the according OperatorKey
 */
public class OperatorInfo {
    private final OperatorType operatorType;
    private final int siteId;
    private final boolean supportsEncryption;

    static Logger logger = LoggerFactory.getLogger(OperatorInfo.class);

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
            return new OperatorInfo(operatorKey.getOperatorType(), operatorKey.getSiteId(), supportsEncryption(rc));
        }
        throw new Exception("Cannot determine the operator type and site id from the profile");
    }

    static boolean supportsEncryption(RoutingContext rc) {
        String appVersion = rc.request().getHeader(AppVersionHeader);
        if (appVersion == null) {
            logger.warn("AppVersion header is missing.");
            return false;
        }
        String[] versions = appVersion.split(";");
        for (String version : versions) {
            if (version.startsWith("uid2-operator=")) {
                String operatorVersion = version.substring("uid2-operator=".length());
                boolean isSupported = isVersionGreaterOrEqual(operatorVersion, ConfigStore.Global.getOrDefault(encryptionSupportVersion, "9999"));
                logger.debug("Operator version: {}, {}",
                        operatorVersion, isSupported ? "Supports encryption" : "Does not support encryption");
                return isSupported;
            }
        }
        logger.warn("No operator version found in AppVersion header.");
        return false;
    }

    /*
    Returns if the version of a semvar v1 is greater or equal to v2
     */
    static boolean isVersionGreaterOrEqual(String v1, String v2) {
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