package com.uid2.core.util;

import com.uid2.core.Const;
import com.uid2.shared.secure.gcpoidc.Environment;
import io.vertx.core.json.JsonObject;

public final class GcpOverrideCheckConfig {
    private final String configuredEnvironment;
    private final Environment coreEnvironment;
    private final boolean enforce;

    private GcpOverrideCheckConfig(String configuredEnvironment, Environment coreEnvironment, boolean enforce) {
        this.configuredEnvironment = configuredEnvironment;
        this.coreEnvironment = coreEnvironment;
        this.enforce = enforce;
    }

    public static GcpOverrideCheckConfig fromConfig(JsonObject config) {
        Object envValue = config.getValue(Const.Config.DeploymentEnvironmentProp);
        String configuredEnvironment = envValue == null ? null : envValue.toString().trim();
        Object enforceValue = config.getValue(Const.Config.GcpEnforceEnvOverrideChecksProp);
        boolean enforce = enforceValue instanceof Boolean
                ? (Boolean) enforceValue
                : enforceValue != null && Boolean.parseBoolean(enforceValue.toString().trim());
        return new GcpOverrideCheckConfig(configuredEnvironment, Environment.fromString(configuredEnvironment), enforce);
    }

    public Environment getCoreEnvironment() {
        return coreEnvironment;
    }

    public boolean isEnforced() {
        return enforce;
    }

    public String describe() {
        if (coreEnvironment != null) {
            return String.format("core environment=%s, enforced=%s", coreEnvironment.getName(), enforce);
        }
        if (configuredEnvironment == null || configuredEnvironment.isEmpty()) {
            return String.format("skipped (%s not set)", Const.Config.DeploymentEnvironmentProp);
        }
        return String.format("skipped (%s=\"%s\" not recognised)", Const.Config.DeploymentEnvironmentProp, configuredEnvironment);
    }
}
