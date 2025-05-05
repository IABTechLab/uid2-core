package com.uid2.core;

import com.google.auth.oauth2.GoogleCredentials;
import com.uid2.core.model.ConfigStore;
import com.uid2.core.model.Constants;
import com.uid2.core.model.SecretStore;
import com.uid2.core.service.AttestationService;
import com.uid2.core.service.OperatorJWTTokenProvider;
import com.uid2.core.vertx.CoreVerticle;
import com.uid2.core.vertx.Endpoints;
import com.uid2.shared.Const;
import com.uid2.shared.Utils;
import com.uid2.shared.attest.AttestationTokenService;
import com.uid2.shared.attest.IAttestationTokenService;
import com.uid2.shared.attest.JwtService;
import com.uid2.shared.auth.EnclaveIdentifierProvider;
import com.uid2.shared.auth.RotatingOperatorKeyProvider;
import com.uid2.shared.store.reader.RotatingCloudEncryptionKeyProvider;
import com.uid2.shared.cloud.CloudUtils;
import com.uid2.shared.cloud.EmbeddedResourceStorage;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.jmx.AdminApi;
import com.uid2.shared.secure.*;
import com.uid2.shared.secure.nitro.InMemoryAWSCertificateStore;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.scope.GlobalScope;
import com.uid2.shared.util.HTTPPathMetricFilter;
import com.uid2.shared.vertx.RotatingStoreVerticle;
import com.uid2.shared.vertx.VertxUtils;
import com.uid2.shared.health.HealthManager;
import com.uid2.shared.health.PodTerminationMonitor;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.config.MeterFilter;
import io.micrometer.prometheus.PrometheusMeterRegistry;
import io.micrometer.prometheus.PrometheusRenameFilter;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.core.file.FileSystem;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.micrometer.Label;
import io.vertx.micrometer.MetricsDomain;
import io.vertx.micrometer.MicrometerMetricsOptions;
import io.vertx.micrometer.VertxPrometheusOptions;
import io.vertx.micrometer.backends.BackendRegistries;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.management.*;
import java.lang.management.ManagementFactory;
import java.util.*;

public class Main {
    private static final Logger LOGGER = LoggerFactory.getLogger(CoreVerticle.class);
    private static final int VERTX_WORKER_POOL_SIZE = 1000; // Cannot set this in config file because it's needed on Vertx init

    public static void main(String[] args) {
        final String vertxConfigPath = System.getProperty(Const.Config.VERTX_CONFIG_PATH_PROP);
        if (vertxConfigPath != null) {
            LOGGER.info("Running CUSTOM CONFIG mode, config: {}", vertxConfigPath);
        } else if (!Utils.isProductionEnvironment()) {
            LOGGER.info("Running LOCAL DEBUG mode, config: {}", Const.Config.LOCAL_CONFIG_PATH);
            System.setProperty(Const.Config.VERTX_CONFIG_PATH_PROP, Const.Config.LOCAL_CONFIG_PATH);
        } else {
            LOGGER.info("Running PRODUCTION mode, config: {}", Const.Config.OVERRIDE_CONFIG_PATH);
        }

        // create AdminApi instance
        try {
            ObjectName objectName = new ObjectName("uid2.core:type=jmx,name=AdminApi");
            MBeanServer server = ManagementFactory.getPlatformMBeanServer();
            server.registerMBean(AdminApi.instance, objectName);
        } catch (InstanceAlreadyExistsException | MBeanRegistrationException | NotCompliantMBeanException | MalformedObjectNameException e) {
            LOGGER.error(e.getMessage());
            System.exit(-1);
        }

        VertxPrometheusOptions promOptions = getPrometheusOptions();
        MicrometerMetricsOptions metricOptions = getMetricOptions(promOptions);
        setupMetrics(metricOptions);
        VertxOptions vertxOptions = getVertxOptions(metricOptions);
        Vertx vertx = Vertx.vertx(vertxOptions);

        VertxUtils.createConfigRetriever(vertx).getConfig(ar -> {
            if (ar.failed()) {
                LOGGER.error("failed to load config: {}", ar.cause().toString());
                System.exit(-1);
            }

            JsonObject config = ar.result();
            ConfigStore.Global.load(config);
            SecretStore.Global.load(config);

            HealthManager.instance.registerGenericComponent(new PodTerminationMonitor(config.getInteger("pod_termination_check_interval", 3000)));

            boolean useStorageMock = Optional.ofNullable(ConfigStore.Global.getBoolean("storage_mock")).orElse(false);
            ICloudStorage cloudStorage;
            if (useStorageMock) {
                cloudStorage = new EmbeddedResourceStorage(Main.class).withUrlPrefix(ConfigStore.Global.getOrDefault("storage_mock_url_prefix", ""));
            } else {
                cloudStorage = CloudUtils.createStorage(SecretStore.Global.get(Const.Config.CoreS3BucketProp), config);

                int expiryInSeconds = ConfigStore.Global.getInteger("pre_signed_url_expiry");
                cloudStorage.setPreSignedUrlExpiry(expiryInSeconds);
            }

            try {
                createVertxMetrics();

                CloudPath operatorMetadataPath = new CloudPath(config.getString(Const.Config.OperatorsMetadataPathProp));
                GlobalScope operatorScope = new GlobalScope(operatorMetadataPath);
                RotatingOperatorKeyProvider operatorKeyProvider = new RotatingOperatorKeyProvider(cloudStorage, cloudStorage, operatorScope);
                RotatingStoreVerticle operatorRotatingVerticle = new RotatingStoreVerticle("operators", 60000, operatorKeyProvider);
                vertx.deployVerticle(operatorRotatingVerticle);

                String enclaveMetadataPath = SecretStore.Global.get(EnclaveIdentifierProvider.ENCLAVES_METADATA_PATH);
                EnclaveIdentifierProvider enclaveIdProvider = new EnclaveIdentifierProvider(cloudStorage, enclaveMetadataPath);
                RotatingStoreVerticle enclaveRotatingVerticle = new RotatingStoreVerticle("enclaves", 60000, enclaveIdProvider);
                vertx.deployVerticle(enclaveRotatingVerticle);

                CloudPath cloudEncryptionKeyMetadataPath = new CloudPath(config.getString(Const.Config.CloudEncryptionKeysMetadataPathProp));
                GlobalScope cloudEncryptionKeyScope = new GlobalScope(cloudEncryptionKeyMetadataPath);
                RotatingCloudEncryptionKeyProvider cloudEncryptionKeyProvider = new RotatingCloudEncryptionKeyProvider(cloudStorage, cloudEncryptionKeyScope);
                RotatingStoreVerticle cloudEncryptionKeyRotatingVerticle = new RotatingStoreVerticle("cloud_encryption_keys", 60000, cloudEncryptionKeyProvider);
                vertx.deployVerticle(cloudEncryptionKeyRotatingVerticle);

                String corePublicUrl = ConfigStore.Global.get(Const.Config.CorePublicUrlProp);
                AttestationService attestationService = new AttestationService()
                        .with("trusted", new TrustedCoreAttestationService())
                        .with("aws-nitro", new NitroCoreAttestationService(new InMemoryAWSCertificateStore(), corePublicUrl));

                // try read GoogleCredentials
                GoogleCredentials googleCredentials = CloudUtils.getGoogleCredentialsFromConfig(config);
                if (googleCredentials != null) {
                    Set<String> enclaveParams = null;
                    String params = config.getString(Const.Config.GcpEnclaveParamsProp);
                    if (params != null) {
                        enclaveParams = Set.of(params.split(","));
                    }

                    // enable gcp-vmid attestation if requested
                    attestationService
                            .with("gcp-vmid", new GcpVmidCoreAttestationService(googleCredentials, enclaveParams));
                }

                var maaServerBaseUrl = ConfigStore.Global.getOrDefault(com.uid2.core.Const.Config.MaaServerBaseUrlProp, "https://sharedeus.eus.attest.azure.net");
                attestationService.with("azure-cc", new AzureCCCoreAttestationService(maaServerBaseUrl, ConfigStore.Global.get(Const.Config.CorePublicUrlProp)));

                attestationService.with("gcp-oidc", new GcpOidcCoreAttestationService(corePublicUrl));

                OperatorJWTTokenProvider operatorJWTTokenProvider = new OperatorJWTTokenProvider(config);

                IAttestationTokenService attestationTokenService = new AttestationTokenService(
                        SecretStore.Global.get(Constants.AttestationEncryptionKeyName),
                        SecretStore.Global.get(Constants.AttestationEncryptionSaltName),
                        SecretStore.Global.getIntegerOrDefault(Constants.AttestationTokenLifetimeInSeconds, 7200)
                );

                JwtService jwtService = new JwtService(config);
                FileSystem fileSystem = vertx.fileSystem();

                vertx.deployVerticle(() -> {
                    try {
                        return new CoreVerticle(cloudStorage, operatorKeyProvider, attestationService, attestationTokenService, enclaveIdProvider, operatorJWTTokenProvider, jwtService, cloudEncryptionKeyProvider, fileSystem);
                    } catch (Exception e) {
                        LOGGER.error("failed to deploy core verticle: {}", e.getMessage());
                        System.exit(-1);
                        return null;
                    }
                }, new DeploymentOptions().setInstances(ConfigStore.Global.getInteger(com.uid2.core.Const.Config.ServiceInstancesProp)));
            } catch (Exception e) {
                LOGGER.error("failed to initialize core verticle: {}", e.getMessage());
                System.exit(-1);
            }
        });
    }

    private static void setupMetrics(MicrometerMetricsOptions metricOptions) {
        BackendRegistries.setupBackend(metricOptions, null);

        // As of now default backend registry should have been created
        if (BackendRegistries.getDefaultNow() instanceof PrometheusMeterRegistry prometheusRegistry) {
            // see also https://micrometer.io/docs/registry/prometheus
            prometheusRegistry.config()
                    // providing common renaming for prometheus metric, e.g. "hello.world" to "hello_world"
                    .meterFilter(new PrometheusRenameFilter())
                    .meterFilter(MeterFilter.replaceTagValues(Label.HTTP_PATH.toString(),
                            actualPath -> HTTPPathMetricFilter.filterPath(actualPath, Endpoints.pathSet())))
                    // Don't record metrics for 404s.
                    .meterFilter(MeterFilter.deny(id ->
                            id.getName().startsWith(MetricsDomain.HTTP_SERVER.getPrefix()) &&
                                    Objects.equals(id.getTag(Label.HTTP_CODE.toString()), "404")))
                    // adding common labels
                    .commonTags("application", "uid2-core");

            // wire my monitoring system to global static state, see also https://micrometer.io/docs/concepts
            Metrics.addRegistry(prometheusRegistry);
        }

        // retrieve image version (will unify when uid2-common is used)
        String version = Optional.ofNullable(System.getenv("IMAGE_VERSION")).orElse("unknown");
        Gauge.builder("app.status", () -> 1)
                .description("application version and status")
                .tags("version", version)
                .register(Metrics.globalRegistry);
    }

    private static void createVertxMetrics() {
        Gauge.builder("uid2.vertx_service_instances", () -> ConfigStore.Global.getInteger(com.uid2.core.Const.Config.ServiceInstancesProp))
                .description("gauge for number of vertx service instances requested")
                .register(Metrics.globalRegistry);

        Gauge.builder("uid2.vertx_worker_pool_size", () -> VERTX_WORKER_POOL_SIZE)
                .description("gauge for vertx worker pool size requested")
                .register(Metrics.globalRegistry);

        Gauge.builder("uid2.vertx_event_loop_threads", () -> VertxOptions.DEFAULT_EVENT_LOOP_POOL_SIZE)
                .description("gauge for number of vertx event loop threads")
                .register(Metrics.globalRegistry);
    }

    private static VertxOptions getVertxOptions(MicrometerMetricsOptions metricOptions) {
        final int threadBlockedCheckInterval = Utils.isProductionEnvironment()
                ? 60 * 1000
                : 3600 * 1000;

        return new VertxOptions()
                .setMetricsOptions(metricOptions)
                .setBlockedThreadCheckInterval(threadBlockedCheckInterval)
                .setWorkerPoolSize(VERTX_WORKER_POOL_SIZE);
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
