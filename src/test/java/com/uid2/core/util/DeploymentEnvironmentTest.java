package com.uid2.core.util;

import com.uid2.shared.secure.gcpoidc.Environment;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class DeploymentEnvironmentTest {
    @ParameterizedTest
    @CsvSource({"prod,true", "PROD,false", "integ,true", "integ,false"})
    void knownValuesMap(String value, boolean required) {
        Environment expected = value.equalsIgnoreCase("prod") ? Environment.Production : Environment.Integration;
        assertEquals(expected, DeploymentEnvironment.toGcpEnvironment(value, required));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void testMapsToNull(boolean required) {
        assertNull(DeploymentEnvironment.toGcpEnvironment("test", required));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void unsetAllowedWhenNotRequired(String value) {
        assertNull(DeploymentEnvironment.toGcpEnvironment(value, false));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void unsetRejectedWhenRequired(String value) {
        assertThrows(IllegalArgumentException.class, () -> DeploymentEnvironment.toGcpEnvironment(value, true));
    }

    @ParameterizedTest
    @ValueSource(strings = {"prd", "local", "production"})
    void unknownValuesRejected(String value) {
        assertThrows(IllegalArgumentException.class, () -> DeploymentEnvironment.toGcpEnvironment(value, false));
        assertThrows(IllegalArgumentException.class, () -> DeploymentEnvironment.toGcpEnvironment(value, true));
    }
}
