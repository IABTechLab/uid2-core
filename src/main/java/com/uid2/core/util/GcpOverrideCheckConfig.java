package com.uid2.core.util;

import com.uid2.core.Const;
import com.uid2.shared.secure.gcpoidc.Environment;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;

import java.util.Locale;

public final class GcpOverrideCheckConfig {
    private final String configuredEnvironment;
    private final Environment coreEnvironment;
    private final boolean enforce;

    private GcpOverrideCheckConfig(String configuredEnvironment, String configuredEnforce) {
        this.configuredEnvironment = configuredEnvironment;
        this.coreEnvironment = configuredEnvironment == null ? null : Environment.fromString(configuredEnvironment.toLowerCase(Locale.ROOT));
        this.enforce = parseEnforce(configuredEnforce);
        if (enforce && coreEnvironment == null) {
            throw new IllegalArgumentException(String.format("%s=true requires %s to be prod or integ, given: %s",
                    Const.Config.GcpEnforceEnvOverrideChecksProp, Const.Config.DeploymentEnvironmentProp, configuredEnvironment));
        }
    }

    /**
     * @throws IllegalArgumentException if the enforce flag is not true/false, or enforcement is on without a recognised deployment environment
     */
    public static GcpOverrideCheckConfig fromConfig(JsonObject config) {
        return new GcpOverrideCheckConfig(
                getTrimmedString(config, Const.Config.DeploymentEnvironmentProp),
                getTrimmedString(config, Const.Config.GcpEnforceEnvOverrideChecksProp));
    }

    private static boolean parseEnforce(String value) {
        if (isNullOrEmpty(value) || "false".equalsIgnoreCase(value)) {
            return false;
        }
        if ("true".equalsIgnoreCase(value)) {
            return true;
        }
        throw new IllegalArgumentException(String.format("%s must be true or false, given: %s",
                Const.Config.GcpEnforceEnvOverrideChecksProp, value));
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
            return String.format("skipped (core environment=%s, enforced=%s; checks apply to prod only)", coreEnvironment.getName(), enforce);
        }
        if (isNullOrEmpty(configuredEnvironment)) {
            return String.format("skipped (%s not set)", Const.Config.DeploymentEnvironmentProp);
        }
        return String.format("skipped (%s=\"%s\" not recognised)", Const.Config.DeploymentEnvironmentProp, configuredEnvironment);
    }

    public boolean hasConfigIssue() {
        return !isNullOrEmpty(configuredEnvironment) && coreEnvironment == null;
    }

    public void logStartup(Logger logger) {
        if (hasConfigIssue()) {
            logger.warn("GCP attestation override checks: {}", describe());
        } else {
            logger.info("GCP attestation override checks: {}", describe());
        }
    }

    private static boolean isNullOrEmpty(String value) {
        return value == null || value.isEmpty();
    }
}
