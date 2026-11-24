package com.uid2.core.util;

import com.uid2.shared.secure.gcpoidc.Environment;

public final class DeploymentEnvironment {
    private DeploymentEnvironment() {
    }

    /**
     * Maps Core's deployment_environment to the GCP attestation Environment; null means "not prod or integ".
     *
     * @param required true when Core runs in Kubernetes, so a deployed Core can't start without it.
     */
    public static Environment toGcpEnvironment(String value, boolean required) {
        if (value == null || value.isEmpty()) {
            if (required) {
                throw new IllegalArgumentException("deployment_environment must be set. Expected prod, integ or test.");
            }
            return null;
        }
        if ("test".equalsIgnoreCase(value)) {
            return null;
        }
        Environment environment = Environment.fromString(value);
        if (environment == null) {
            throw new IllegalArgumentException("Unknown deployment_environment: " + value + ". Expected prod, integ or test.");
        }
        return environment;
    }
}
