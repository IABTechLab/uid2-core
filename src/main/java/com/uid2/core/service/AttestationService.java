// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package com.uid2.core.service;

import com.uid2.shared.auth.IOperatorChangeHandler;
import com.uid2.shared.model.EnclaveIdentifier;
import com.uid2.shared.secure.AttestationException;
import com.uid2.shared.secure.AttestationResult;
import com.uid2.shared.secure.IAttestationProvider;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

public class AttestationService implements IOperatorChangeHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(AttestationService.class);

    private final Map<String, IAttestationProvider> protocols;
    private final AtomicReference<Set<EnclaveIdentifier>> activeOperatorIdentifiers;

    public AttestationService() {
        protocols = new HashMap<>();
        activeOperatorIdentifiers = new AtomicReference<>(new HashSet<>());
    }

    public AttestationService with(String name, IAttestationProvider protocol) {
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

    private IAttestationProvider get(String name) throws AttestationService.NotFound {
        IAttestationProvider handle = this.protocols.get(name);
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
