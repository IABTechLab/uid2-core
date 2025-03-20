package com.uid2.core.util;
import com.uid2.shared.auth.IAuthorizable;
import com.uid2.shared.auth.OperatorKey;
import com.uid2.shared.auth.OperatorType;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
        return Boolean.parseBoolean(rc.request().getHeader("Encrypted"));
    }
}