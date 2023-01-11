package com.uid2.core.util;
import com.uid2.shared.auth.IAuthorizable;
import com.uid2.shared.auth.OperatorKey;
import com.uid2.shared.auth.OperatorType;
import io.vertx.ext.web.RoutingContext;

import static com.uid2.shared.middleware.AuthMiddleware.API_CLIENT_PROP;

/**
 * Given a logged in operator, determine its site id and if it's a public/private
 * Typically this should be extracting these details from the according OperatorKey
 */
public class OperatorInfo {
    private final OperatorType operatorType;
    private final int siteId;

    public OperatorType getOperatorType() {
        return operatorType;
    }

    public int getSiteId() {
        return siteId;
    }

    public OperatorInfo(OperatorType operatorType, int siteId) {
        this.operatorType = operatorType;
        this.siteId = siteId;
    }

    public static OperatorInfo getOperatorInfo(RoutingContext rc) throws Exception {
        IAuthorizable profile = (IAuthorizable)  rc.data().get(API_CLIENT_PROP);
        if (profile instanceof OperatorKey) {
            OperatorKey operatorKey = (OperatorKey) profile;
            return new OperatorInfo(operatorKey.getOperatorType(), operatorKey.getSiteId());
        }
        throw new Exception("Cannot determine the operator type and site id from the profile");
    }
}