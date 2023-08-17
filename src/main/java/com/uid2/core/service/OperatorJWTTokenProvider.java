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
import java.security.NoSuchAlgorithmException;

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
    public String getOptOutJWTToken(String operatorKey, String name, Role role, Integer siteId, String enclaveId, String enclaveType, String operatorVersion, Instant expiresAt) throws JWTTokenProvider.JwtSigningException {
        return this.getJWTToken(this.config.getString(Const.Config.CorePublicUrlProp), this.config.getString(Const.Config.OptOutUrlProp), operatorKey, name, role, siteId, enclaveId, enclaveType, operatorVersion, expiresAt);
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
    public String getCoreJWTToken(String operatorKey, String name, Role role, Integer siteId, String enclaveId, String enclaveType, String operatorVersion, Instant expiresAt) throws JWTTokenProvider.JwtSigningException {
        return this.getJWTToken(this.config.getString(Const.Config.CorePublicUrlProp), this.config.getString(Const.Config.CorePublicUrlProp), operatorKey, name, role, siteId, enclaveId, enclaveType, operatorVersion, expiresAt);
    }

    private String getJWTToken(String issuer, String audience, String operatorKey, String name, Role role, Integer siteId, String enclaveId, String enclaveType, String operatorVersion, Instant expiresAt) throws JWTTokenProvider.JwtSigningException {

        byte[] keyBytes = operatorKey.getBytes();
        MessageDigest md = createMessageDigest();
        byte[] hashBytes = md.digest(keyBytes);
        String keyHash = Utils.toBase64String(hashBytes);

        HashMap<String, String> claims = new HashMap<>();
        claims.put("iss", issuer);
        claims.put("sub", keyHash);
        claims.put("aud", audience);
        claims.put("name", name);
        claims.put("role", role.toString());
        claims.put("siteId", siteId.toString());
        claims.put("enclaveId", enclaveId);
        claims.put("enclaveType", enclaveType);
        claims.put("operatorVersion", operatorVersion);

        LOGGER.debug(String.format("Creating token with: Issuer: %s, Audience: %s, Role: %s, SiteId: %s, EnclaveId: %s, EnclaveType: %s, OperatorVersion: %s", audience, issuer, role, siteId, enclaveId, enclaveType, operatorVersion));
        return this.jwtTokenProvider.getJWT(expiresAt, this.clock.instant(), claims);
    }

    private MessageDigest createMessageDigest() {
        try {
            return MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
