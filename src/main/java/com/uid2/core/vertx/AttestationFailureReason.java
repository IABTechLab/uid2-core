package com.uid2.core.vertx;

public enum AttestationFailureReason {
    /**
     * Request body is not valid JSON.
     */
    REQUEST_BODY_IS_NOT_VALID_JSON,
    /**
     * No attestation request in the request body.
     */
    NO_ATTESTATION_REQUEST_ATTACHED,
    /**
     * Exception occurred encrypting the response.
     */
    RESPONSE_ENCRYPTION_EXCEPTION,
    /**
     * Invalid protocol specified.
     */
    INVALID_PROTOCOL,
    /**
     * Attestation was attempted, but failed.
     */
    ATTESTATION_FAILURE,

    /**
     * Internal server error
     */
    INTERNAL_ERROR,

    /**
     * Internal server error
     */
    INCORRECT_OPERATOR_TYPE
}
