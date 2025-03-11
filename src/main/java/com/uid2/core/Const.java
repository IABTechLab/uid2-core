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

    public static class Config extends com.uid2.shared.Const.Config {
        public static final String ServiceInstancesProp = "service_instances";

        public static final String KmsRegionProp = "aws_kms_region";
        public static final String KmsAccessKeyIdProp = "aws_kms_access_key_id";
        public static final String KmsSecretAccessKeyProp = "aws_kms_secret_access_key";
        public static final String KmsEndpointProp = "aws_kms_endpoint";
    }

    public static final String OPERATOR_CONFIG_PATH = "conf/operator/operator-config.json";
}
