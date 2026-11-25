package com.uid2.core.util;

import com.uid2.shared.secure.gcpoidc.Environment;

public final class DeploymentEnvironment {
    private DeploymentEnvironment() {
    }

    /**
     * Maps Core's deployment_environment to the GCP attestation Environment; null (test) means the declared environment check is not applied.
     */
    public static Environment toGcpEnvironment(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("deployment_environment must be set. Expected prod, integ or test.");
        }
        String trimmed = value.trim();
        if ("test".equalsIgnoreCase(trimmed)) {
            return null;
        }
        Environment environment = Environment.fromString(trimmed);
        if (environment == null) {
            throw new IllegalArgumentException("Unknown deployment_environment: " + trimmed + ". Expected prod, integ or test.");
        }
        return environment;
    }
}
