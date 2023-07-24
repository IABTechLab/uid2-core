package com.uid2.core.service;

import com.uid2.core.model.ConfigStore;
import com.uid2.shared.Const;
import com.uid2.shared.auth.Role;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.kms.KmsClient;

import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Set;
import java.util.stream.Collectors;

public class OptOutJWTTokenProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(OptOutJWTTokenProvider.class);
    private final JWTTokenProvider jwtTokenProvider;
    private final Clock clock;

    public OptOutJWTTokenProvider() {
        this(new JWTTokenProvider(KmsClient.builder()), Clock.systemUTC());
    }

    public OptOutJWTTokenProvider(JWTTokenProvider jwtTokenProvider, Clock clock) {

        this.jwtTokenProvider = jwtTokenProvider;
        this.clock = clock;
    }

    /*
        Returns a JWT that is given to the operator. This is then presented by the operator to
        OptOut when the operator makes calls to OptOut.
        The claims we will add are:
        "iss" : the config value for issuer, something like https://core-prod.uidapi.com
        "sub" : the name of the operator as registered in the Admin site
        "aud" : the url of the optout service that this token can be used with https://optout-prod.uidapi.com
        "exp" : the expiry date time of the token, set to be the same as the expiry of the attestation token
        "iat" : the current date time
     */
    public String getOptOutJWTToken(String name, Set<Role> roles, Integer siteId, String enclaveId, String enclaveType, String operatorVersion, Instant expiresAt) throws JWTTokenProvider.JwtSigningException {
        String roleString = String.join(",", roles.stream().map(Object::toString).collect(Collectors.toList()));
        HashMap<String, String> claims = new HashMap<>();
        claims.put("iss", ConfigStore.Global.get(Const.Config.CorePublicUrlProp));
        claims.put("sub", name);
        claims.put("aud", ConfigStore.Global.get(Const.Config.OptOutUrlProp));
        claims.put("exp", Long.toString(expiresAt.getEpochSecond()));
        claims.put("iat", Long.toString(this.clock.instant().getEpochSecond()));
        claims.put("roles", roleString);
        claims.put("siteId", siteId.toString());
        claims.put("enclaveId", enclaveId);
        claims.put("enclaveType", enclaveType);
        claims.put("operatorVersion", operatorVersion);

        LOGGER.debug(String.format("Creating token with: Roles: %s, SiteId: %s, EnclaveId: %s, EnclaveType: %s, OperatorVersion: %s", roleString, siteId, enclaveId, enclaveType, operatorVersion));
        String token = this.jwtTokenProvider.getJWT(claims);
        return token;
    }
}
