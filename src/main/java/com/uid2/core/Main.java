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

package com.uid2.core;

import com.google.auth.oauth2.GoogleCredentials;
import com.uid2.core.model.ConfigStore;
import com.uid2.core.model.Constants;
import com.uid2.core.model.SecretStore;
import com.uid2.core.service.AttestationService;
import com.uid2.core.vertx.CoreVerticle;
import com.uid2.shared.Const;
import com.uid2.shared.Utils;
import com.uid2.shared.attest.AttestationTokenService;
import com.uid2.shared.attest.IAttestationTokenService;
import com.uid2.shared.auth.EnclaveIdentifierProvider;
import com.uid2.shared.auth.RotatingOperatorKeyProvider;
import com.uid2.shared.cloud.CloudUtils;
import com.uid2.shared.cloud.EmbeddedResourceStorage;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.jmx.AdminApi;
import com.uid2.shared.secure.AzureAttestationProvider;
import com.uid2.shared.secure.GcpVmidAttestationProvider;
import com.uid2.shared.secure.NitroAttestationProvider;
import com.uid2.shared.secure.nitro.InMemoryAWSCertificateStore;
import com.uid2.shared.vertx.RotatingStoreVerticle;
import com.uid2.shared.vertx.VertxUtils;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.prometheus.PrometheusMeterRegistry;
import io.micrometer.prometheus.PrometheusRenameFilter;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.WebClient;
import io.vertx.micrometer.Label;
import io.vertx.micrometer.MicrometerMetricsOptions;
import io.vertx.micrometer.VertxPrometheusOptions;
import io.vertx.micrometer.backends.BackendRegistries;

import javax.management.*;
import java.lang.management.ManagementFactory;
import java.util.*;

public class Main {

    public static void main(String[] args) {
        final String vertxConfigPath = System.getProperty(Const.Config.VERTX_CONFIG_PATH_PROP);
        if (vertxConfigPath != null) {
            System.out.format("Running CUSTOM CONFIG mode, config: %s\n", vertxConfigPath);
        } else if (!Utils.isProductionEnvionment()) {
            System.out.format("Running LOCAL DEBUG mode, config: %s\n", Const.Config.LOCAL_CONFIG_PATH);
            System.setProperty(Const.Config.VERTX_CONFIG_PATH_PROP, Const.Config.LOCAL_CONFIG_PATH);
        } else {
            System.out.format("Running PRODUCTION mode, config: %s\n", Const.Config.OVERRIDE_CONFIG_PATH);
        }

        // create AdminApi instance
        try {
            ObjectName objectName = new ObjectName("uid2.core:type=jmx,name=AdminApi");
            MBeanServer server = ManagementFactory.getPlatformMBeanServer();
            server.registerMBean(AdminApi.instance, objectName);
        } catch (InstanceAlreadyExistsException | MBeanRegistrationException | NotCompliantMBeanException | MalformedObjectNameException e) {
            System.err.format("%s", e.getMessage());
            System.exit(-1);
        }

        VertxPrometheusOptions promOptions = getPrometheusOptions();
        MicrometerMetricsOptions metricOptions = getMetricOptions(promOptions);
        setupMetrics(metricOptions);
        VertxOptions vertxOptions = getVertxOptions(metricOptions);
        Vertx vertx = Vertx.vertx(vertxOptions);

        /*
        CommandLine commandLine = parseArgs(args);
        String configPath = commandLine.getOptionValue("config").toString();
        String secretsPath = commandLine.getOptionValue("secrets").toString();
        ConfigStore.Global.load(configPath);
        SecretStore.Global.load(secretsPath);
         */

        VertxUtils.createConfigRetriever(vertx).getConfig(ar -> {
            if (ar.failed()) {
                System.out.println("failed to load config: " + ar.cause().toString());
                System.exit(-1);
            }

            JsonObject config = ar.result();
            ConfigStore.Global.load(config);
            SecretStore.Global.load(config);

            boolean useStorageMock = Optional.ofNullable(ConfigStore.Global.getBoolean("storage_mock")).orElse(false);
            ICloudStorage cloudStorage = null;
            if (useStorageMock) {
                cloudStorage = new EmbeddedResourceStorage(Main.class).withUrlPrefix(ConfigStore.Global.getOrDefault("storage_mock_url_prefix", ""));
            } else {
                cloudStorage = CloudUtils.createStorage(SecretStore.Global.get(Const.Config.CoreS3BucketProp), config);

                int expiryInSeconds = ConfigStore.Global.getInteger("pre_signed_url_expiry");
                cloudStorage.setPreSignedUrlExpiry(expiryInSeconds);
            }

            RotatingStoreVerticle enclaveRotatingVerticle = null;
            RotatingStoreVerticle operatorRotatingVerticle = null;
            CoreVerticle coreVerticle = null;
            try {
                String operatorMetadataPath = SecretStore.Global.get(Const.Config.OperatorsMetadataPathProp);
                RotatingOperatorKeyProvider operatorKeyProvider = new RotatingOperatorKeyProvider(cloudStorage, cloudStorage, operatorMetadataPath);
                operatorRotatingVerticle = new RotatingStoreVerticle("operators", 60000, operatorKeyProvider);

                String enclaveMetadataPath = SecretStore.Global.get(EnclaveIdentifierProvider.ENCLAVES_METADATA_PATH);
                EnclaveIdentifierProvider enclaveIdProvider = new EnclaveIdentifierProvider(cloudStorage, enclaveMetadataPath);
                enclaveRotatingVerticle = new RotatingStoreVerticle("enclaves", 60000, enclaveIdProvider);

                AttestationService attestationService = new AttestationService()
                    .with("azure-sgx", new AzureAttestationProvider(
                        ConfigStore.Global.getOrDefault("maa_server_base_url", "https://sharedeus.eus.attest.azure.net"),
                        WebClient.create(vertx)))
                    .with("aws-nitro", new NitroAttestationProvider(new InMemoryAWSCertificateStore()));

                // try read GoogleCredentials
                GoogleCredentials googleCredentials = CloudUtils.getGoogleCredentialsFromConfig(config);
                if (googleCredentials != null) {
                    Set<String> enclaveParams = null;
                    String params = config.getString(Const.Config.GcpEnclaveParamsProp);
                    if (params != null) {
                        enclaveParams = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(params.split(","))));
                    }

                    // enable gcp-vmid attestation if requested
                    attestationService
                        .with("gcp-vmid", new GcpVmidAttestationProvider(googleCredentials, enclaveParams));
                }

                IAttestationTokenService attestationTokenService = new AttestationTokenService(
                        SecretStore.Global.get(Constants.AttestationEncryptionKeyName),
                        SecretStore.Global.get(Constants.AttestationEncryptionSaltName)
                );

                coreVerticle = new CoreVerticle(cloudStorage, operatorKeyProvider, attestationService, attestationTokenService, enclaveIdProvider);
            } catch (Exception e) {
                System.out.println("failed to initialize core verticle: " + e.getMessage());
                System.exit(-1);
            }

            vertx.deployVerticle(enclaveRotatingVerticle);
            vertx.deployVerticle(operatorRotatingVerticle);
            vertx.deployVerticle(coreVerticle);
        });
    }

    private static void setupMetrics(MicrometerMetricsOptions metricOptions) {
        BackendRegistries.setupBackend(metricOptions);

        // As of now default backend registry should have been created
        if (BackendRegistries.getDefaultNow() instanceof PrometheusMeterRegistry) {
            PrometheusMeterRegistry prometheusRegistry = (PrometheusMeterRegistry) BackendRegistries.getDefaultNow();

            // see also https://micrometer.io/docs/registry/prometheus
            prometheusRegistry.config()
                // providing common renaming for prometheus metric, e.g. "hello.world" to "hello_world"
                .meterFilter(new PrometheusRenameFilter())
                // adding common labels
                .commonTags("application", "uid2-core");

            // wire my monitoring system to global static state, see also https://micrometer.io/docs/concepts
            Metrics.addRegistry(prometheusRegistry);
        }

        // retrieve image version (will unify when uid2-common is used)
        String version = Optional.ofNullable(System.getenv("IMAGE_VERSION")).orElse("unknown");
        Gauge appStatus = Gauge
            .builder("app.status", () -> 1)
            .description("application version and status")
            .tags("version", version)
            .register(Metrics.globalRegistry);
    }

    /*
    private static CommandLine parseArgs(String[] args) {
        final CLI cli = CLI.create("uid2-core")
            .setSummary("run uid2 core service")
            .addOption(new Option()
                .setLongName("config")
                .setDescription("path to configuration file")
                .setRequired(true))
            .addOption(new Option()
                .setLongName("secrets")
                .setDescription("path to secrets file")
                .setRequired(true));
        return cli.parse(Arrays.asList(args));
    }
     */

    private static VertxOptions getVertxOptions(MicrometerMetricsOptions metricOptions) {
        final int threadBlockedCheckInterval = Utils.isProductionEnvionment()
            ? 60 * 1000
            : 3600 * 1000;

        return new VertxOptions()
            .setMetricsOptions(metricOptions)
            .setBlockedThreadCheckInterval(threadBlockedCheckInterval);
    }

    private static MicrometerMetricsOptions getMetricOptions(VertxPrometheusOptions promOptions) {
        return new MicrometerMetricsOptions()
            .setPrometheusOptions(promOptions)
            .setLabels(EnumSet.of(Label.HTTP_METHOD, Label.HTTP_CODE, Label.HTTP_PATH))
            .setJvmMetricsEnabled(true)
            .setEnabled(true);
    }

    private static VertxPrometheusOptions getPrometheusOptions() {
        final int portOffset = Utils.getPortOffset();
        return new VertxPrometheusOptions()
            .setStartEmbeddedServer(true)
            .setEmbeddedServerOptions(new HttpServerOptions().setPort(Const.Port.PrometheusPortForCore + portOffset))
            .setEnabled(true);
    }
}
