package com.uid2.core.util;

import com.uid2.shared.secure.gcpoidc.Environment;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class DeploymentEnvironmentTest {
    @ParameterizedTest
    @ValueSource(strings = {"prod", "PROD", "integ", "prod\n", " prod", " Integ ", "integ\t"})
    void knownValuesMap(String value) {
        Environment expected = value.trim().equalsIgnoreCase("prod") ? Environment.Production : Environment.Integration;
        assertEquals(expected, DeploymentEnvironment.toGcpEnvironment(value));
    }

    @ParameterizedTest
    @ValueSource(strings = {"test", "TEST", " test", "test\n"})
    void testMapsToNull(String value) {
        assertNull(DeploymentEnvironment.toGcpEnvironment(value));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\n"})
    void unsetRejected(String value) {
        assertThrows(IllegalArgumentException.class, () -> DeploymentEnvironment.toGcpEnvironment(value));
    }

    @ParameterizedTest
    @ValueSource(strings = {"prd", "local", "production"})
    void unknownValuesRejected(String value) {
        assertThrows(IllegalArgumentException.class, () -> DeploymentEnvironment.toGcpEnvironment(value));
    }
}
