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

package com.uid2.core.tool;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.uid2.shared.Const;
import com.uid2.shared.Utils;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.auth.Role;
import com.uid2.shared.auth.RotatingClientKeyProvider;
import com.uid2.shared.cloud.CloudUtils;
import com.uid2.shared.cloud.DryRunStorageMock;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.cloud.LocalStorageMock;
import com.uid2.shared.vertx.VertxUtils;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.core.cli.*;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

public class ClientKeyTool {
    private JsonObject config;
    private boolean isVerbose = false;
    private boolean isYes = false;
    private final RotatingClientKeyProvider clientKeyProvider;
    private final ICloudStorage clientKeyCloudStorage;
    private final ObjectWriter jsonWriter;
    private final ObjectWriter onelineJsonWriter;
    private final String clientKeyPrefix;

    ClientKeyTool(JsonObject config) throws Exception {
        this.config = config;
        this.clientKeyPrefix = config.getString("client_key_prefix");
        this.clientKeyCloudStorage = CloudUtils.createStorage(config.getString("core_s3_bucket"), config);
        String metadataPath = config.getString("clients_metadata_path");
        this.clientKeyProvider = new RotatingClientKeyProvider(clientKeyCloudStorage, metadataPath);
        clientKeyProvider.loadContent();

        ObjectMapper mapper = new ObjectMapper();
        this.onelineJsonWriter = mapper.writer();

        DefaultPrettyPrinter pp = new DefaultPrettyPrinter();
        pp.indentArraysWith(DefaultIndenter.SYSTEM_LINEFEED_INSTANCE);
        this.jsonWriter = mapper.writer(pp);
    }

    public static void main(String[] args) throws Exception {
        VertxOptions options = new VertxOptions()
            .setBlockedThreadCheckInterval(60*60*1000);
        Vertx vertx = Vertx.vertx(options);
        final String vertxConfigPath = System.getProperty(Const.Config.VERTX_CONFIG_PATH_PROP);
        if (vertxConfigPath != null) {
            System.out.format("Running CUSTOM CONFIG mode, config: %s\n", vertxConfigPath);
        }
        else if (!Utils.isProductionEnvionment()) {
            System.out.format("Running LOCAL DEBUG mode, config: %s\n", Const.Config.LOCAL_CONFIG_PATH);
            System.setProperty(Const.Config.VERTX_CONFIG_PATH_PROP, Const.Config.LOCAL_CONFIG_PATH);
        } else {
            System.out.format("Running PRODUCTION mode, config: %s\n", Const.Config.OVERRIDE_CONFIG_PATH);
        }

        VertxUtils.createConfigRetriever(vertx).getConfig(ar -> {
            try {
                ClientKeyTool tool = new ClientKeyTool(ar.result());
                tool.run(args);
            } catch (Exception e) {
                e.printStackTrace();
                vertx.close();
                System.exit(1);
            } finally {
                vertx.close();
            }
        });
    }

    public void run(String[] args) throws Exception {
        CommandLine cli = parseArgs(args);
        this.isVerbose = cli.isFlagEnabled("verbose");
        if (this.isVerbose) {
            System.out.println("VERBOSE on");
        }
        this.isYes = cli.isFlagEnabled("yes");
        if (this.isYes) {
            System.out.println("Pre-confirmed to proceed with potentially DESTRUCTIVE operation...");
        }

        Set<String> supportedCommands = new HashSet<>();
        supportedCommands.add("list");
        supportedCommands.add("add");
        supportedCommands.add("del");
        supportedCommands.add("update");
        supportedCommands.add("rollback");

        String command = cli.getArgumentValue("command");
        if (!supportedCommands.contains(command)) {
            System.err.println("Unknown command: " + command);
        } else if ("add".equals(command)) {
            String name = cli.getOptionValue("name");
            Integer siteId = cli.getOptionValue("site");
            if (siteId == null) siteId = Const.Data.DefaultClientSiteId;
            checkOptionExistence(name, command, "name");
            Set<Role> roles = getRolesFromOption(cli);
            runAdd(name, siteId, roles);
        } else if ("del".equals(command)) {
            String name = cli.getOptionValue("name");
            String key = cli.getOptionValue("key");
            if (name != null) runDelByName(name);
            else if (key != null) runDelByKey(key);
            else System.err.println("Command del needs either -name or -key provided");
        } else if ("update".equals(command)) {
            String name = cli.getOptionValue("name");
            checkOptionExistence(name, command, "name");
            Integer siteId = cli.getOptionValue("site");
            Set<Role> roles = getRolesFromOption(cli);
            runUpdate(name, siteId, roles);
        } else if ("list".equals(command)) {
            runList();
        } else if ("rollback".equals(command)) {
            runRollback();
        }
    }

    private Set<Role> getRolesFromOption(CommandLine cli) throws Exception {
        String rolesOption = cli.getOptionValue("roles");
        if(rolesOption == null) return null;
        try {
            Set<Role> roles = Arrays.stream(rolesOption.split(","))
                .map(r -> r.trim().toUpperCase())
                .map(r -> Role.valueOf(r))
                .collect(Collectors.toSet());
            return roles;
        } catch (Exception e) {
            throw new Exception("Unable to parse roles: " + rolesOption, e);
        }
    }

    private void checkOptionExistence(Object val, String command, String option) throws Exception {
        if (val == null) {
            throw new Exception("option -" + option + " is required for command " + command);
        }
    }

    private CommandLine parseArgs(String[] args) {
        final CLI cli = CLI.create("client-key-tool")
            .setSummary("A tool for managing client keys for uid2-core")
            .addArgument(new Argument()
                .setArgName("command")
                .setDescription("command to run, can be one of: list, add, del, rollback")
                .setRequired(true))
            .addOption(new Option()
                .setLongName("name")
                .setShortName("n")
                .setDescription("find or specify client by the name")
                .setRequired(false))
            .addOption(new Option()
                .setLongName("roles")
                .setShortName("r")
                .setDescription("specify role names"))
            .addOption(new Option()
                .setLongName("key")
                .setShortName("o")
                .setDescription("find client by the key")
                .setRequired(false))
            .addOption(new TypedOption<Integer>()
                .setLongName("site")
                .setShortName("s")
                .setDescription("specify client site id")
                .setType(Integer.class)
                .setRequired(false))
            .addOption(new Option()
                .setLongName("verbose")
                .setShortName("v")
                .setDescription("allow verbose logging")
                .setFlag(true)
                .setRequired(false))
            .addOption(new Option()
                .setLongName("yes")
                .setShortName("y")
                .setDescription("confirm to proceed with operation")
                .setFlag(true)
                .setRequired(false));
        return cli.parse(Arrays.asList(args));
    }

    private void runAdd(String name, int siteId, Set<Role> roles) throws Exception {
        Optional<ClientKey> existingClient = this.clientKeyProvider.getAll()
            .stream().filter(c -> c.getName().equals(name))
            .findFirst();
        if (existingClient.isPresent()) {
            throw new IllegalArgumentException(name + " already existed");
        }

        if (roles == null || roles.isEmpty()) {
            throw new IllegalArgumentException("must specify client role(s)");
        }

        List<ClientKey> clients = this.clientKeyProvider.getAll()
            .stream().sorted((a, b) -> (int)(a.getCreated() - b.getCreated()))
            .collect(Collectors.toList());

        // create a random key
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String key = Utils.toBase64String(bytes);
        if (this.clientKeyPrefix != null) key = this.clientKeyPrefix + key;

        // add new client to array
        Instant created = Instant.now();
        ClientKey newClient = new ClientKey(key, created)
            .withNameAndContact(name)
            .withSiteId(siteId)
            .withRoles(roles);
        if (!newClient.hasValidSiteId()) {
            throw new IllegalArgumentException("invalid site id");
        }
        clients.add(newClient);

        Path newMetadataFile = Files.createTempFile("clients-metadata", ".json");
        Path newClientsFile = Files.createTempFile("clients", ".json");
        RotatingClientKeyProvider newClientKeyProvider = this.createLocalProvider(
            this.clientKeyProvider.getMetadata(), clients, newMetadataFile, newClientsFile);

        int errors = this.verifyProviders(clientKeyProvider, newClientKeyProvider);
        ClientKey newClientFromFile = newClientKeyProvider.getClientKey(key);
        if (!newClient.equals(newClientFromFile)) {
            System.err.println("Error: new key not written as expected " + name);
            System.err.println("Expected: " + onelineJsonWriter.writeValueAsString(newClient));
            System.err.println("Actual: " + onelineJsonWriter.writeValueAsString(newClientFromFile));
            ++errors;
        }

        if (errors > 0) {
            System.err.println("Found " + errors + " errors");
            System.exit(1);
        }

        System.out.println("Verification passed, uploading...");
        final ICloudStorage uploadStorage;
        if (this.isYes) {
            System.out.println("WARNING: uploading to cloud storage, which is potentially DESTRUCTIVE");
            uploadStorage = this.clientKeyCloudStorage;
        } else {
            System.out.println("WARNING: uploading to dry-run mock storage, specify -yes to do actual upload");
            uploadStorage = new DryRunStorageMock(this.isVerbose);
        }

        this.bumpUpVersionAndUpload(uploadStorage, this.clientKeyProvider, clients);
        System.out.format("UID 2.0 API-KEY for %s: %s\n", name, key);
        System.out.println("New config uploaded");
    }

    private void bumpUpVersionAndUpload(ICloudStorage uploadStorage, RotatingClientKeyProvider provider,
                                        Collection<ClientKey> clients)
        throws Exception {
        long generated = Instant.now().getEpochSecond();

        JsonObject metadata = provider.getMetadata();
        // bump up metadata version
        metadata.put("version", metadata.getLong("version") + 1);
        metadata.put("generated", generated);

        // get location to upload
        String location = metadata.getJsonObject("client_keys").getString("location");

        // crate local temp for old clients
        Path localTemp = Files.createTempFile("clients-old", ".json");
        Files.copy(uploadStorage.download(location), localTemp, StandardCopyOption.REPLACE_EXISTING);

        // make backups
        uploadStorage.upload(localTemp.toString(), location + ".bak");
        uploadStorage.upload(localTemp.toString(), location + "." + String.valueOf(generated) + ".bak");

        // generate new clients
        Path newClientsFile = Files.createTempFile("clients", ".json");
        byte[] contentBytes = jsonWriter.writeValueAsString(clients).getBytes(StandardCharsets.UTF_8);
        Files.write(newClientsFile, contentBytes, StandardOpenOption.CREATE);

        // generate new metadata
        Path newMetadataFile = Files.createTempFile("clients-metadata", ".json");
        byte[] mdBytes = Json.encodePrettily(metadata).getBytes(StandardCharsets.UTF_8);
        Files.write(newMetadataFile, mdBytes, StandardOpenOption.CREATE);

        // upload new clients
        uploadStorage.upload(newClientsFile.toString(), location);

        // upload new metadata
        uploadStorage.upload(newMetadataFile.toString(), provider.getMetadataPath());
    }

    private int verifyProviders(RotatingClientKeyProvider smaller, RotatingClientKeyProvider bigger)
        throws JsonProcessingException {
        int errors = 0;
        for (ClientKey c : smaller.getAll()) {
            ClientKey d = bigger.getClientKey(c.getKey());
            if (!c.equals(d)) {
                System.err.println("Error: key differs " + c.getName());
                System.err.println("Before: " + onelineJsonWriter.writeValueAsString(c));
                System.err.println("After: " + onelineJsonWriter.writeValueAsString(d));
                ++errors;
            }
        }

        if (smaller.getAll().size() + 1 != bigger.getAll().size()) {
            System.err.println("Two providers are expected to have sizes differ by 1");
            System.err.println("But one is " + smaller.getAll().size() + ", another is " + bigger.getAll().size());
            ++errors;
        }

        return errors;
    }

    private RotatingClientKeyProvider createLocalProvider(JsonObject metadata, Collection<ClientKey> clients,
                                  Path newMetadataFile, Path newClientsFile) throws Exception {
        // bump up metadata version
        metadata.put("version", metadata.getLong("version") + 1);
        metadata.put("generated", Instant.now().getEpochSecond());

        // to generate a loadable local provider, location needs to be updated as well
        metadata.getJsonObject("client_keys").put("location", newClientsFile.toString());

        byte[] mdBytes = Json.encodePrettily(metadata).getBytes(StandardCharsets.UTF_8);
        Files.write(newMetadataFile, mdBytes, StandardOpenOption.CREATE);

        byte[] contentBytes = jsonWriter.writeValueAsString(clients).getBytes(StandardCharsets.UTF_8);
        Files.write(newClientsFile, contentBytes, StandardOpenOption.CREATE);

        // load from local files
        RotatingClientKeyProvider newClientKeyProvider = new RotatingClientKeyProvider(
            new LocalStorageMock(),
            newMetadataFile.toString()
        );
        newClientKeyProvider.loadContent();

        return newClientKeyProvider;
    }

    private void runDelByName(String name) throws Exception {
        Optional<ClientKey> existingClient = this.clientKeyProvider.getAll()
            .stream().filter(c -> c.getName().equals(name))
            .findFirst();
        if (!existingClient.isPresent()) {
            throw new IllegalArgumentException("name: " + name + " not found");
        }

        List<ClientKey> clients = this.clientKeyProvider.getAll().stream()
            .filter(c -> !c.getName().equals(name))
            .sorted((a, b) -> (int)(a.getCreated() - b.getCreated()))
            .collect(Collectors.toList());

        this.uploadAfterDelete(existingClient.get(), clients);
    }

    private void runDelByKey(String key) throws Exception {
        Optional<ClientKey> existingClient = this.clientKeyProvider.getAll()
            .stream().filter(c -> c.getKey().equals(key))
            .findFirst();
        if (!existingClient.isPresent()) {
            throw new IllegalArgumentException("key: " + key + " not found");
        }

        List<ClientKey> clients = this.clientKeyProvider.getAll().stream()
            .filter(c -> !c.getKey().equals(key))
            .sorted((a, b) -> (int)(a.getCreated() - b.getCreated()))
            .collect(Collectors.toList());

        this.uploadAfterDelete(existingClient.get(), clients);
    }

    private void runUpdate(String name, Integer siteId, Set<Role> newRoles) throws Exception {
        Optional<ClientKey> existingClient = this.clientKeyProvider.getAll()
            .stream().filter(c -> c.getName().equals(name))
            .findFirst();
        if (!existingClient.isPresent()) {
            throw new IllegalArgumentException("name: " + name + " not found");
        }

        ClientKey c = existingClient.get();
        String oldRolesSpec = getRolesSpec(c.getRoles());
        System.out.format("old - name: %s, siteId: %d, roles: %s\n", c.getName(), c.getSiteId(), oldRolesSpec);

        if (siteId != null) {
            c.withSiteId(siteId);
            if (!c.hasValidSiteId()) {
                throw new IllegalArgumentException("invalid site id");
            }
        }

        if (newRoles != null) {
            if (newRoles.isEmpty()) {
                throw new IllegalArgumentException("client must have at least one role");
            }
            c.withRoles(newRoles);
        }

        String newRolesSpec = getRolesSpec(c.getRoles());
        System.out.format("new - name: %s, siteId: %d, roles: %s\n", c.getName(), c.getSiteId(), newRolesSpec);

        this.uploadAfterUpdate(this.clientKeyProvider.getAll());
    }

    private String getRolesSpec(Set<Role> roles) {
        return String.join(",", roles.stream().map(r -> r.toString()).collect(Collectors.toList()));
    }

    private void runList() {
        Collection<ClientKey> collection = this.clientKeyProvider.getAll();
        for (ClientKey c : collection) {
            String roles = getRolesSpec(c.getRoles());
            if (this.isVerbose) {
                System.out.format("name: %s, siteId: %d, key: %s, roles: %s\n", c.getName(), c.getSiteId(), c.getKey(), roles);
            } else {
                System.out.format("name: %s, siteId: %d, roles: %s\n", c.getName(), c.getSiteId(), roles);
            }
        }
        System.out.println("Total " + collection.size() + " client keys in the config");
    }

    private void runRollback() throws Exception {
        final ICloudStorage uploadStorage;
        if (this.isYes) {
            System.out.println("WARNING: uploading to cloud storage, which is potentially DESTRUCTIVE");
            uploadStorage = this.clientKeyCloudStorage;
        } else {
            System.out.println("WARNING: uploading to dry-run mock storage, specify -yes to do actual upload");
            uploadStorage = new DryRunStorageMock(this.isVerbose);
        }

        this.bumpUpVersionAndRollback(uploadStorage, this.clientKeyProvider);
        System.out.println("Rollback config uploaded");
    }

    private void uploadAfterUpdate(Collection<ClientKey> clients) throws Exception {
        final ICloudStorage uploadStorage;
        if (this.isYes) {
            System.out.println("WARNING: uploading to cloud storage, which is potentially DESTRUCTIVE");
            uploadStorage = this.clientKeyCloudStorage;
        } else {
            System.out.println("WARNING: uploading to dry-run mock storage, specify -yes to do actual upload");
            uploadStorage = new DryRunStorageMock(this.isVerbose);
        }

        this.bumpUpVersionAndUpload(uploadStorage, this.clientKeyProvider, clients);
        System.out.println("New config uploaded");
    }

    private void uploadAfterDelete(ClientKey clientKey, Collection<ClientKey> clients) throws Exception {
        Path newMetadataFile = Files.createTempFile("clients-metadata", ".json");
        Path newClientsFile = Files.createTempFile("clients", ".json");
        RotatingClientKeyProvider newClientKeyProvider = this.createLocalProvider(
            this.clientKeyProvider.getMetadata(), clients, newMetadataFile, newClientsFile);

        int errors = this.verifyProviders(newClientKeyProvider, clientKeyProvider);
        ClientKey deletingClient = newClientKeyProvider.getClientKey(clientKey.getKey());
        if (deletingClient != null) {
            System.err.println("Error: key is not deleted as expected " + clientKey.getName());
            System.err.println(onelineJsonWriter.writeValueAsString(deletingClient));
            ++errors;
        }

        if (errors > 0) {
            System.err.println("Found " + errors + " errors");
            System.exit(1);
        }

        System.out.println("Verification passed, uploading...");
        final ICloudStorage uploadStorage;
        if (this.isYes) {
            System.out.println("WARNING: uploading to cloud storage, which is potentially DESTRUCTIVE");
            uploadStorage = this.clientKeyCloudStorage;
        } else {
            System.out.println("WARNING: uploading to dry-run mock storage, specify -yes to do actual upload");
            uploadStorage = new DryRunStorageMock(this.isVerbose);
        }

        this.bumpUpVersionAndUpload(uploadStorage, this.clientKeyProvider, clients);
        System.out.println("New config uploaded");
    }

    private void bumpUpVersionAndRollback(ICloudStorage uploadStorage, RotatingClientKeyProvider provider)
        throws Exception {
        long generated = Instant.now().getEpochSecond();

        JsonObject metadata = provider.getMetadata();
        // bump up metadata version
        metadata.put("version", metadata.getLong("version") + 1);
        metadata.put("generated", generated);

        // get location to upload
        String location = metadata.getJsonObject("client_keys").getString("location");
        String backup = location + ".bak";

        // check if backup exists
        if (this.clientKeyCloudStorage.list(backup).size() == 0) {
            throw new IllegalArgumentException("Unable to locate backup file to revert to: " + backup);
        }

        // crate local temp for old clients
        Path localTemp = Files.createTempFile("clients-old", ".json");
        Files.copy(uploadStorage.download(location), localTemp, StandardCopyOption.REPLACE_EXISTING);

        // crate local temp for backup clients
        Path localBackup = Files.createTempFile("clients-bak", ".json");
        Files.copy(uploadStorage.download(backup), localBackup, StandardCopyOption.REPLACE_EXISTING);

        // make backups
        uploadStorage.upload(localTemp.toString(), location + ".bak");
        uploadStorage.upload(localTemp.toString(), location + "." + String.valueOf(generated) + ".bak");

        // generate new metadata
        Path newMetadataFile = Files.createTempFile("clients-metadata", ".json");
        byte[] mdBytes = Json.encodePrettily(metadata).getBytes(StandardCharsets.UTF_8);
        Files.write(newMetadataFile, mdBytes, StandardOpenOption.CREATE);

        // upload new clients
        uploadStorage.upload(localBackup.toString(), location);

        // upload new metadata
        uploadStorage.upload(newMetadataFile.toString(), provider.getMetadataPath());
    }
}
