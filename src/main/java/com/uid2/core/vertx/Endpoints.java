package com.uid2.core.vertx;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum Endpoints {
    OPS_HEALTHCHECK("/ops/healthcheck"),
    ATTEST("/attest"),
    ATTEST_GET_TOKEN("/attest/get_token"),
    CLOUD_ENCRYPTION_KEYS_RETRIEVE("/cloud_encryption_keys/retrieve"),
    SITES_REFRESH("/sites/refresh"),
    KEY_REFRESH("/key/refresh"),
    KEY_ACL_REFRESH("/key/acl/refresh"),
    KEY_KEYSET_REFRESH("/key/keyset/refresh"),
    KEY_KEYSET_KEYS_REFRESH("/key/keyset-keys/refresh"),
    SALT_REFRESH("/salt/refresh"),
    CLIENTS_REFRESH("/clients/refresh"),
    CLIENT_SIDE_KEYPAIRS_REFRESH("/client_side_keypairs/refresh"),
    SERVICES_REFRESH("/services/refresh"),
    SERVICE_LINKS_REFRESH("/service_links/refresh"),
    OPERATORS_REFRESH("/operators/refresh"),
    PARTNERS_REFRESH("/partners/refresh"),
    CONFIG("/config");

    private final String path;

    Endpoints(final String path) {
        this.path = path;
    }

    public static Set<String> pathSet() {
        return Stream.of(Endpoints.values()).map(Endpoints::toString).collect(Collectors.toSet());
    }

    @Override
    public String toString() {
        return path;
    }
}
