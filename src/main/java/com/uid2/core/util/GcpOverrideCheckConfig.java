package com.uid2.core.util;

import com.uid2.core.Const;
import com.uid2.shared.secure.gcpoidc.Environment;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;

public final class GcpOverrideCheckConfig {
    private final String configuredEnvironment;
    private final Environment coreEnvironment;
    private final String configuredEnforce;
    private final boolean enforce;

    private GcpOverrideCheckConfig(String configuredEnvironment, String configuredEnforce) {
        this.configuredEnvironment = configuredEnvironment;
        this.coreEnvironment = Environment.fromString(configuredEnvironment);
        this.configuredEnforce = configuredEnforce;
        this.enforce = "true".equalsIgnoreCase(configuredEnforce);
    }

    public static GcpOverrideCheckConfig fromConfig(JsonObject config) {
        return new GcpOverrideCheckConfig(
                getTrimmedString(config, Const.Config.DeploymentEnvironmentProp),
                getTrimmedString(config, Const.Config.GcpEnforceEnvOverrideChecksProp));
    }

    private static String getTrimmedString(JsonObject config, String key) {
        Object value = config.getValue(key);
        return value == null ? null : value.toString().trim();
    }

    public Environment getCoreEnvironment() {
        return coreEnvironment;
    }

    public boolean isEnforced() {
        return enforce;
    }

    public String describe() {
        if (coreEnvironment == Environment.Production) {
            return String.format("core environment=%s, enforced=%s", coreEnvironment.getName(), enforce);
        }
        if (coreEnvironment != null) {
            return String.format("skipped (core environment=%s; checks apply to prod only)", coreEnvironment.getName());
        }
        if (isNullOrEmpty(configuredEnvironment)) {
            return String.format("skipped (%s not set)", Const.Config.DeploymentEnvironmentProp);
        }
        return String.format("skipped (%s=\"%s\" not recognised)", Const.Config.DeploymentEnvironmentProp, configuredEnvironment);
    }

    public boolean hasConfigIssue() {
        boolean unrecognisedEnvironment = !isNullOrEmpty(configuredEnvironment) && coreEnvironment == null;
        boolean unrecognisedEnforce = !isNullOrEmpty(configuredEnforce)
                && !"true".equalsIgnoreCase(configuredEnforce) && !"false".equalsIgnoreCase(configuredEnforce);
        boolean enforcedWithoutEnvironment = enforce && coreEnvironment == null;
        return unrecognisedEnvironment || unrecognisedEnforce || enforcedWithoutEnvironment;
    }

    public void logStartup(Logger logger) {
        if (hasConfigIssue()) {
            logger.warn("GCP attestation override checks: {} ({}={}, {}={})", describe(),
                    Const.Config.DeploymentEnvironmentProp, configuredEnvironment,
                    Const.Config.GcpEnforceEnvOverrideChecksProp, configuredEnforce);
        } else {
            logger.info("GCP attestation override checks: {}", describe());
        }
    }

    private static boolean isNullOrEmpty(String value) {
        return value == null || value.isEmpty();
    }
}
