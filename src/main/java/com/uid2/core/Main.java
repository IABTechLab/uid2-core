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
import com.uid2.shared.model.CloudEncryptionKey;
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
import io.vertx.core.http.impl.HttpUtils;
import io.vertx.core.json.JsonObject;
import io.vertx.micrometer.Label;
import io.vertx.micrometer.MetricsDomain;
import io.vertx.micrometer.MicrometerMetricsOptions;
import io.vertx.micrometer.VertxPrometheusOptions;
import io.vertx.micrometer.backends.BackendRegistries;

import javax.management.*;
import java.lang.management.ManagementFactory;
import java.util.*;

public class Main {

    private static final int vertxServiceInstances = 1;

    public static void main(String[] args) {
        final String vertxConfigPath = System.getProperty(Const.Config.VERTX_CONFIG_PATH_PROP);
        if (vertxConfigPath != null) {
            System.out.format("Running CUSTOM CONFIG mode, config: %s\n", vertxConfigPath);
        } else if (!Utils.isProductionEnvironment()) {
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
            RotatingStoreVerticle cloudEncryptionKeyRotatingVerticle = null;
            CoreVerticle coreVerticle = null;
            try {
                CloudPath operatorMetadataPath = new CloudPath(config.getString(Const.Config.OperatorsMetadataPathProp));
                GlobalScope operatorScope = new GlobalScope(operatorMetadataPath);
                RotatingOperatorKeyProvider operatorKeyProvider = new RotatingOperatorKeyProvider(cloudStorage, cloudStorage, operatorScope);
                operatorRotatingVerticle = new RotatingStoreVerticle("operators", 60000, operatorKeyProvider);

                String enclaveMetadataPath = SecretStore.Global.get(EnclaveIdentifierProvider.ENCLAVES_METADATA_PATH);
                EnclaveIdentifierProvider enclaveIdProvider = new EnclaveIdentifierProvider(cloudStorage, enclaveMetadataPath);
                enclaveRotatingVerticle = new RotatingStoreVerticle("enclaves", 60000, enclaveIdProvider);

                CloudPath cloudEncryptionKeyMetadataPath = new CloudPath(config.getString(Const.Config.CloudEncryptionKeysMetadataPathProp));
                GlobalScope cloudEncryptionKeyScope = new GlobalScope(cloudEncryptionKeyMetadataPath);
                RotatingCloudEncryptionKeyProvider cloudEncryptionKeyProvider = new RotatingCloudEncryptionKeyProvider(cloudStorage, cloudEncryptionKeyScope);
                cloudEncryptionKeyRotatingVerticle = new RotatingStoreVerticle("cloud_encryption_keys", 60000, cloudEncryptionKeyProvider);

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
                        enclaveParams = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(params.split(","))));
                    }

                    // enable gcp-vmid attestation if requested
                    attestationService
                            .with("gcp-vmid", new GcpVmidCoreAttestationService(googleCredentials, enclaveParams));
                }

                var maaServerBaseUrl = ConfigStore.Global.getOrDefault(com.uid2.core.Const.Config.MaaServerBaseUrlProp, "https://sharedeus.eus.attest.azure.net");
                attestationService.with("azure-cc", new AzureCCCoreAttestationService(maaServerBaseUrl, ConfigStore.Global.get(Const.Config.CorePublicUrlProp)));
                attestationService.with("azure-cc-aks", new AzureCCAksCoreAttestationService(maaServerBaseUrl, ConfigStore.Global.get(Const.Config.CorePublicUrlProp)));

                attestationService.with("gcp-oidc", new GcpOidcCoreAttestationService(corePublicUrl));

                OperatorJWTTokenProvider operatorJWTTokenProvider = new OperatorJWTTokenProvider(config);
                
                IAttestationTokenService attestationTokenService = new AttestationTokenService(
                        SecretStore.Global.get(Constants.AttestationEncryptionKeyName),
                        SecretStore.Global.get(Constants.AttestationEncryptionSaltName),
                        SecretStore.Global.getIntegerOrDefault(Constants.AttestationTokenLifetimeInSeconds, 7200)
                );

                JwtService jwtService = new JwtService(config);
                FileSystem fileSystem = vertx.fileSystem();
                coreVerticle = new CoreVerticle(cloudStorage, operatorKeyProvider, attestationService, attestationTokenService, enclaveIdProvider, operatorJWTTokenProvider, jwtService, cloudEncryptionKeyProvider, fileSystem);
            } catch (Exception e) {
                System.out.println("failed to initialize core verticle: " + e.getMessage());
                System.exit(-1);
            }

            createVertxInstancesMetric();
            createVertxEventLoopsMetric();

            vertx.deployVerticle(enclaveRotatingVerticle);
            vertx.deployVerticle(operatorRotatingVerticle);
            vertx.deployVerticle(cloudEncryptionKeyRotatingVerticle);
            vertx.deployVerticle(coreVerticle, new DeploymentOptions().setInstances(vertxServiceInstances));
        });
    }

    private static void setupMetrics(MicrometerMetricsOptions metricOptions) {
        BackendRegistries.setupBackend(metricOptions, null);

        // As of now default backend registry should have been created
        if (BackendRegistries.getDefaultNow() instanceof PrometheusMeterRegistry) {
            PrometheusMeterRegistry prometheusRegistry = (PrometheusMeterRegistry) BackendRegistries.getDefaultNow();

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
        Gauge appStatus = Gauge
                .builder("app.status", () -> 1)
                .description("application version and status")
                .tags("version", version)
                .register(Metrics.globalRegistry);
    }

    private static void createVertxInstancesMetric() {
        Gauge.builder("uid2.vertx_service_instances", () -> vertxServiceInstances)
                .description("gauge for number of vertx service instances requested")
                .register(Metrics.globalRegistry);
    }

    private static void createVertxEventLoopsMetric() {
        Gauge.builder("uid2.vertx_event_loop_threads", () -> VertxOptions.DEFAULT_EVENT_LOOP_POOL_SIZE)
                .description("gauge for number of vertx event loop threads")
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
        final int threadBlockedCheckInterval = Utils.isProductionEnvironment()
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
