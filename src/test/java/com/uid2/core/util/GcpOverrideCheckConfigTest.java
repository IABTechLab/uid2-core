package com.uid2.core.util;

import com.uid2.shared.secure.gcpoidc.Environment;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class GcpOverrideCheckConfigTest {
    private static GcpOverrideCheckConfig fromConfig(Object environment, Object enforce) {
        JsonObject config = new JsonObject();
        if (environment != null) {
            config.put("deployment_environment", environment);
        }
        if (enforce != null) {
            config.put("gcp_enforce_env_override_checks", enforce);
        }
        return GcpOverrideCheckConfig.fromConfig(config);
    }

    @Test
    void testNotSet() {
        GcpOverrideCheckConfig config = fromConfig(null, null);
        assertNull(config.getCoreEnvironment());
        assertFalse(config.isEnforced());
        assertFalse(config.hasConfigIssue());
        assertEquals("skipped (deployment_environment not set)", config.describe());
    }

    @Test
    void testProdNotEnforced() {
        GcpOverrideCheckConfig config = fromConfig("prod", false);
        assertEquals(Environment.Production, config.getCoreEnvironment());
        assertFalse(config.isEnforced());
        assertFalse(config.hasConfigIssue());
        assertEquals("core environment=prod, enforced=false", config.describe());
    }

    @Test
    void testProdEnforced() {
        GcpOverrideCheckConfig config = fromConfig("prod", true);
        assertEquals(Environment.Production, config.getCoreEnvironment());
        assertTrue(config.isEnforced());
        assertFalse(config.hasConfigIssue());
        assertEquals("core environment=prod, enforced=true", config.describe());
    }

    @Test
    void testProdEnforcedAsString() {
        GcpOverrideCheckConfig config = fromConfig("PROD", "True");
        assertEquals(Environment.Production, config.getCoreEnvironment());
        assertTrue(config.isEnforced());
        assertFalse(config.hasConfigIssue());
    }

    @Test
    void testInteg() {
        GcpOverrideCheckConfig config = fromConfig("integ", true);
        assertEquals(Environment.Integration, config.getCoreEnvironment());
        assertTrue(config.isEnforced());
        assertFalse(config.hasConfigIssue());
        assertEquals("skipped (core environment=integ, enforced=true; checks apply to prod only)", config.describe());
    }

    @Test
    void testUnrecognisedEnvironment() {
        GcpOverrideCheckConfig config = fromConfig("staging", false);
        assertNull(config.getCoreEnvironment());
        assertTrue(config.hasConfigIssue());
        assertEquals("skipped (deployment_environment=\"staging\" not recognised)", config.describe());
    }

    @Test
    void testEnforcedWithoutEnvironment() {
        assertThrows(IllegalArgumentException.class, () -> fromConfig(null, true));
    }

    @Test
    void testEnforcedWithUnrecognisedEnvironment() {
        assertThrows(IllegalArgumentException.class, () -> fromConfig("production", true));
    }

    @Test
    void testUnrecognisedEnforceValue() {
        assertThrows(IllegalArgumentException.class, () -> fromConfig("prod", "yes"));
    }
}
