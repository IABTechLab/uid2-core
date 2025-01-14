package com.uid2.core;

public class Const extends com.uid2.shared.Const {
    public static class RoutingContextData {
        /**
         * The reason for attestation failure.
         */
        public static final String ATTESTATION_FAILURE_REASON_PROP = "attestation-failure-reason";
        /**
         * Any data related to the attestation failure.
         */
        public static final String ATTESTATION_FAILURE_DATA_PROP = "attestation-failure-data";
    }

    public class Config extends com.uid2.shared.Const.Config {
        public static final String KmsAccessKeyIdProp = "kms_aws_access_key_id";
        public static final String KmsSecretAccessKeyProp = "kms_aws_secret_access_key";
        public static final String KmsEndpointProp = "kms_aws_endpoint";
    }

    public static final String OPERATOR_CONFIG_PATH = "conf/operator-config.json";
}