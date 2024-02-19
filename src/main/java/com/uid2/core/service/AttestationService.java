package com.uid2.core.service;

import com.uid2.shared.auth.IOperatorChangeHandler;
import com.uid2.shared.model.EnclaveIdentifier;
import com.uid2.shared.secure.AttestationException;
import com.uid2.shared.secure.AttestationResult;
import com.uid2.shared.secure.ICoreAttestationService;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

public class AttestationService implements IOperatorChangeHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(AttestationService.class);

    private final Map<String, ICoreAttestationService> protocols;
    private final AtomicReference<Set<EnclaveIdentifier>> activeOperatorIdentifiers;

    public AttestationService() {
        protocols = new HashMap<>();
        activeOperatorIdentifiers = new AtomicReference<>(new HashSet<>());
    }

    public AttestationService with(String name, ICoreAttestationService protocol) {
        this.protocols.put(name, protocol);
        return this;
    }

    public void attest(String protocol,
                       String base64EncodedRequest,
                       String base64EncodedPublicKey,
                       Handler<AsyncResult<AttestationResult>> handler)
            throws AttestationService.NotFound {
        this.get(protocol)
                .attest(
                        Base64.getDecoder().decode(base64EncodedRequest),
                        Base64.getDecoder().decode(base64EncodedPublicKey),
                        handler);
    }

    public void registerEnclave(String protocol, String identifier)
            throws AttestationException, AttestationService.NotFound {
        this.get(protocol).registerEnclave(identifier);
    }

    public void unregisterEnclave(String protocol, String identifier)
            throws AttestationException, AttestationService.NotFound {
        this.get(protocol).unregisterEnclave(identifier);
    }

    public List<String> listEnclaves() {
        List<String> res = new ArrayList<>();
        for (String key : this.protocols.keySet()) {
            res.addAll(this.protocols.get(key).getEnclaveAllowlist());
        }
        return res;
    }

    private ICoreAttestationService get(String name) throws AttestationService.NotFound {
        ICoreAttestationService handle = this.protocols.get(name);
        if (handle != null) return handle;
        throw new AttestationService.NotFound(name);
    }

    @Override
    public synchronized void handle(Set<EnclaveIdentifier> newSet) {
        Set<EnclaveIdentifier> oldSet = new HashSet<>(activeOperatorIdentifiers.get());
        Set<EnclaveIdentifier> itemsToAdd = new HashSet<>(newSet);
        itemsToAdd.removeAll(oldSet);
        Set<EnclaveIdentifier> itemsToRemove = oldSet;
        itemsToRemove.removeAll(newSet);

        for (EnclaveIdentifier id : itemsToAdd) {
            try {
                registerEnclave(id.getProtocol(), id.getIdentifier());
            } catch (Exception e) {
                LOGGER.warn("exception while processing enclave profile: " + e.getMessage());
            }
        }

        for (EnclaveIdentifier id : itemsToRemove) {
            try {
                unregisterEnclave(id.getProtocol(), id.getIdentifier());
            } catch (Exception e) {
                LOGGER.warn("exception while processing enclave profile: " + e.getMessage());
            }
        }

        this.activeOperatorIdentifiers.set(newSet);
    }

    public class NotFound extends Exception {
        public NotFound(String protocolName) {
            super(protocolName);
        }
    }
}
