package com.uid2.core.service;

import com.uid2.shared.Const;
import com.uid2.shared.Utils;
import com.uid2.shared.auth.Role;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.kms.KmsClient;

import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Set;
import java.util.stream.Collectors;
import java.security.MessageDigest;

import static com.uid2.shared.Utils.createMessageDigestSHA512;

public class OperatorJWTTokenProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(OperatorJWTTokenProvider.class);
    private final JsonObject config;
    private final JWTTokenProvider jwtTokenProvider;
    private final Clock clock;

    public OperatorJWTTokenProvider(JsonObject config) {
        this(config, new JWTTokenProvider(config, KmsClient.builder()), Clock.systemUTC());
    }

    public OperatorJWTTokenProvider(JsonObject config, JWTTokenProvider jwtTokenProvider, Clock clock) {
        this.config = config;
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
    public String getOptOutJWTToken(String operatorKey, String name, Set<Role> roles, Integer siteId, String enclaveId, String enclaveType, String operatorVersion, Instant expiresAt) throws JWTTokenProvider.JwtSigningException {
        return this.getJWTToken(this.config.getString(Const.Config.CorePublicUrlProp), this.config.getString(Const.Config.OptOutUrlProp), operatorKey, name, roles, siteId, enclaveId, enclaveType, operatorVersion, expiresAt);
    }

    /*
        Returns a JWT that is given to the operator. This is then presented by the operator to
        OptOut when the operator makes calls to Core.
        The claims we will add are:
        "iss" : the config value for issuer, something like https://core-prod.uidapi.com
        "sub" : the name of the operator as registered in the Admin site
        "aud" : the url of the optout service that this token can be used with https://core-prod.uidapi.com
        "exp" : the expiry date time of the token, set to be the same as the expiry of the attestation token
        "iat" : the current date time
     */
    public String getCoreJWTToken(String operatorKey, String name, Set<Role> roles, Integer siteId, String enclaveId, String enclaveType, String operatorVersion, Instant expiresAt) throws JWTTokenProvider.JwtSigningException {
        return this.getJWTToken(this.config.getString(Const.Config.CorePublicUrlProp), this.config.getString(Const.Config.CorePublicUrlProp), operatorKey, name, roles, siteId, enclaveId, enclaveType, operatorVersion, expiresAt);
    }

    private String getJWTToken(String issuer, String audience, String operatorKey, String name, Set<Role> roles, Integer siteId, String enclaveId, String enclaveType, String operatorVersion, Instant expiresAt) throws JWTTokenProvider.JwtSigningException {

        String roleString = String.join(",", roles.stream().map(Object::toString).collect(Collectors.toList()));

        byte[] keyBytes = operatorKey.getBytes();
        MessageDigest md = createMessageDigestSHA512();
        byte[] hashBytes = md.digest(keyBytes);
        String keyHash = Utils.toBase64String(hashBytes);

        HashMap<String, String> claims = new HashMap<>();
        claims.put("iss", issuer);
        claims.put("sub", keyHash);
        claims.put("aud", audience);
        claims.put("name", name);
        claims.put("roles", roleString);
        claims.put("siteId", siteId.toString());
        claims.put("enclaveId", enclaveId);
        claims.put("enclaveType", enclaveType);
        claims.put("operatorVersion", operatorVersion);

        LOGGER.debug(String.format("Creating token with: Issuer: %s, Audience: %s, Roles: %s, SiteId: %s, EnclaveId: %s, EnclaveType: %s, OperatorVersion: %s, Expiry: %s", audience, issuer, roleString, siteId, enclaveId, enclaveType, operatorVersion, expiresAt.getEpochSecond()));
        return this.jwtTokenProvider.getJWT(expiresAt, this.clock.instant(), claims);
    }
}
