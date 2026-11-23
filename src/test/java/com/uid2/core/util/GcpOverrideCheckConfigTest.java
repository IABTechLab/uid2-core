package com.uid2.core.util;

import com.uid2.shared.secure.gcpoidc.Environment;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class GcpOverrideCheckConfigTest {
    @Test
    void testNotSet() {
        GcpOverrideCheckConfig config = GcpOverrideCheckConfig.fromConfig(new JsonObject());
        assertNull(config.getCoreEnvironment());
        assertFalse(config.isEnforced());
        assertEquals("skipped (deployment_environment not set)", config.describe());
    }

    @Test
    void testProdNotEnforced() {
        GcpOverrideCheckConfig config = GcpOverrideCheckConfig.fromConfig(new JsonObject()
                .put("deployment_environment", "prod")
                .put("gcp_enforce_env_override_checks", false));
        assertEquals(Environment.Production, config.getCoreEnvironment());
        assertFalse(config.isEnforced());
        assertEquals("core environment=prod, enforced=false", config.describe());
    }

    @Test
    void testProdEnforced() {
        GcpOverrideCheckConfig config = GcpOverrideCheckConfig.fromConfig(new JsonObject()
                .put("deployment_environment", "prod")
                .put("gcp_enforce_env_override_checks", true));
        assertEquals(Environment.Production, config.getCoreEnvironment());
        assertTrue(config.isEnforced());
        assertEquals("core environment=prod, enforced=true", config.describe());
    }

    @Test
    void testIntegWithStringFlag() {
        GcpOverrideCheckConfig config = GcpOverrideCheckConfig.fromConfig(new JsonObject()
                .put("deployment_environment", "INTEG")
                .put("gcp_enforce_env_override_checks", "true"));
        assertEquals(Environment.Integration, config.getCoreEnvironment());
        assertTrue(config.isEnforced());
        assertEquals("core environment=integ, enforced=true", config.describe());
    }

    @Test
    void testUnrecognisedEnvironment() {
        GcpOverrideCheckConfig config = GcpOverrideCheckConfig.fromConfig(new JsonObject()
                .put("deployment_environment", "staging")
                .put("gcp_enforce_env_override_checks", true));
        assertNull(config.getCoreEnvironment());
        assertTrue(config.isEnforced());
        assertEquals("skipped (deployment_environment=\"staging\" not recognised)", config.describe());
    }
}
