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
import com.uid2.shared.auth.OperatorKey;
import com.uid2.shared.auth.RotatingOperatorKeyProvider;
import com.uid2.shared.cloud.CloudUtils;
import com.uid2.shared.cloud.DryRunStorageMock;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.cloud.LocalStorageMock;
import com.uid2.shared.vertx.VertxUtils;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.core.cli.Argument;
import io.vertx.core.cli.CLI;
import io.vertx.core.cli.CommandLine;
import io.vertx.core.cli.Option;
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

public class OperatorKeyTool {
    private JsonObject config;
    private boolean isVerbose = false;
    private boolean isYes = false;
    private final RotatingOperatorKeyProvider operatorKeyProvider;
    private final ICloudStorage operatorKeyCloudStorage;
    private final ObjectWriter jsonWriter;
    private final ObjectWriter onelineJsonWriter;

    OperatorKeyTool(JsonObject config) throws Exception {
        this.config = config;
        this.operatorKeyCloudStorage = CloudUtils.createStorage(config.getString("core_s3_bucket"), config);
        String metadataPath = config.getString("operators_metadata_path");
        this.operatorKeyProvider = new RotatingOperatorKeyProvider(operatorKeyCloudStorage, operatorKeyCloudStorage, metadataPath);
        operatorKeyProvider.loadContent(operatorKeyProvider.getMetadata());

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
                OperatorKeyTool tool = new OperatorKeyTool(ar.result());
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
        supportedCommands.add("rollback");

        String command = cli.getArgumentValue("command");
        if (!supportedCommands.contains(command)) {
            System.err.println("Unknown command: " + command);
        } else if ("add".equals(command)) {
            String name = cli.getOptionValue("name");
            String attestationProtocol = cli.getOptionValue("protocol");
            runAdd(name, attestationProtocol);
        } else if ("del".equals(command)) {
            String name = cli.getOptionValue("name");
            String key = cli.getOptionValue("key");
            if (name != null) runDelByName(name);
            else if (key != null) runDelByKey(key);
            else System.err.println("Command del needs either -name or -key provided");
        } else if ("list".equals(command)) {
            runList();
        } else if ("rollback".equals(command)) {
            runRollback();
        }
    }

    private CommandLine parseArgs(String[] args) {
        final CLI cli = CLI.create("operator-key-tool")
                .setSummary("A tool for managing operator keys for uid2-core")
                .addArgument(new Argument()
                        .setArgName("command")
                        .setDescription("command to run, can be one of: list, add, del, rollback")
                        .setRequired(true))
                .addOption(new Option()
                        .setLongName("name")
                        .setShortName("n")
                        .setDescription("find or specify operator by the name")
                        .setRequired(false))
                .addOption(new Option()
                        .setLongName("protocol")
                        .setShortName("p")
                        .setDescription("specify attestation protocol")
                        .setRequired(false))
                .addOption(new Option()
                        .setLongName("key")
                        .setShortName("k")
                        .setDescription("find operator by the key")
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

    private void runAdd(String name, String attestationProtocol) throws Exception {
        Optional<OperatorKey> existingOperator = this.operatorKeyProvider.getAll()
                .stream().filter(c -> c.getName().equals(name))
                .findFirst();
        if (existingOperator.isPresent()) {
            throw new IllegalArgumentException(name + " already existed");
        }

        List<OperatorKey> operators = this.operatorKeyProvider.getAll()
                .stream().sorted((a, b) -> (int)(a.getCreated() - b.getCreated()))
                .collect(Collectors.toList());

        // create a random key
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String key = Utils.toBase64String(bytes);

        // add new operator to array
        Instant created = Instant.now();
        OperatorKey newOperator = new OperatorKey(key, name, name, attestationProtocol, created.getEpochSecond());
        operators.add(newOperator);

        Path newMetadataFile = Files.createTempFile("operators-metadata", ".json");
        Path newOperatorsFile = Files.createTempFile("operators", ".json");
        RotatingOperatorKeyProvider newOperatorKeyProvider = this.createLocalProvider(
                this.operatorKeyProvider.getMetadata(), operators, newMetadataFile, newOperatorsFile);

        int errors = this.verifyProviders(operatorKeyProvider, newOperatorKeyProvider);
        OperatorKey newOperatorFromFile = newOperatorKeyProvider.getOperatorKey(key);
        if (!newOperator.equals(newOperatorFromFile)) {
            System.err.println("Error: new key not written as expected " + name);
            System.err.println("Expected: " + onelineJsonWriter.writeValueAsString(newOperator));
            System.err.println("Actual: " + onelineJsonWriter.writeValueAsString(newOperatorFromFile));
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
            uploadStorage = this.operatorKeyCloudStorage;
        } else {
            System.out.println("WARNING: uploading to dry-run mock storage, specify -yes to do actual upload");
            uploadStorage = new DryRunStorageMock(this.isVerbose);
        }

        this.bumpUpVersionAndUpload(uploadStorage, this.operatorKeyProvider, operators);
        System.out.format("UID 2.0 Operator API-KEY for %s: %s\n", name, key);
        System.out.println("New config uploaded");
    }

    private void bumpUpVersionAndUpload(ICloudStorage uploadStorage, RotatingOperatorKeyProvider provider,
                                        Collection<OperatorKey> operators)
            throws Exception {
        long generated = Instant.now().getEpochSecond();

        JsonObject metadata = provider.getMetadata();
        // bump up metadata version
        metadata.put("version", metadata.getLong("version") + 1);
        metadata.put("generated", generated);

        // get location to upload
        String location = metadata.getJsonObject("operators").getString("location");

        // crate local temp for old operators
        Path localTemp = Files.createTempFile("operators-old", ".json");
        Files.copy(uploadStorage.download(location), localTemp, StandardCopyOption.REPLACE_EXISTING);

        // make backups
        uploadStorage.upload(localTemp.toString(), location + ".bak");
        uploadStorage.upload(localTemp.toString(), location + "." + String.valueOf(generated) + ".bak");

        // generate new operators
        Path newOperatorsFile = Files.createTempFile("operators", ".json");
        byte[] contentBytes = jsonWriter.writeValueAsString(operators).getBytes(StandardCharsets.UTF_8);
        Files.write(newOperatorsFile, contentBytes, StandardOpenOption.CREATE);

        // generate new metadata
        Path newMetadataFile = Files.createTempFile("operators-metadata", ".json");
        byte[] mdBytes = Json.encodePrettily(metadata).getBytes(StandardCharsets.UTF_8);
        Files.write(newMetadataFile, mdBytes, StandardOpenOption.CREATE);

        // upload new operators
        uploadStorage.upload(newOperatorsFile.toString(), location);

        // upload new metadata
        uploadStorage.upload(newMetadataFile.toString(), provider.getMetadataPath());
    }

    private int verifyProviders(RotatingOperatorKeyProvider smaller, RotatingOperatorKeyProvider bigger)
            throws JsonProcessingException {
        int errors = 0;
        for (OperatorKey c : smaller.getAll()) {
            OperatorKey d = bigger.getOperatorKey(c.getKey());
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

    private RotatingOperatorKeyProvider createLocalProvider(JsonObject metadata, Collection<OperatorKey> operators,
                                                          Path newMetadataFile, Path newOperatorsFile) throws Exception {
        // bump up metadata version
        metadata.put("version", metadata.getLong("version") + 1);
        metadata.put("generated", Instant.now().getEpochSecond());

        // to generate a loadable local provider, location needs to be updated as well
        metadata.getJsonObject("operators").put("location", newOperatorsFile.toString());

        byte[] mdBytes = Json.encodePrettily(metadata).getBytes(StandardCharsets.UTF_8);
        Files.write(newMetadataFile, mdBytes, StandardOpenOption.CREATE);

        byte[] contentBytes = jsonWriter.writeValueAsString(operators).getBytes(StandardCharsets.UTF_8);
        Files.write(newOperatorsFile, contentBytes, StandardOpenOption.CREATE);

        // load from local files
        LocalStorageMock localStorage = new LocalStorageMock();
        RotatingOperatorKeyProvider newOperatorKeyProvider = new RotatingOperatorKeyProvider(
                localStorage,
                localStorage,
                newMetadataFile.toString()
        );
        newOperatorKeyProvider.loadContent(newOperatorKeyProvider.getMetadata());

        return newOperatorKeyProvider;
    }

    private void runDelByName(String name) throws Exception {
        Optional<OperatorKey> existingOperator = this.operatorKeyProvider.getAll()
                .stream().filter(c -> c.getName().equals(name))
                .findFirst();
        if (!existingOperator.isPresent()) {
            throw new IllegalArgumentException("name: " + name + " not found");
        }

        List<OperatorKey> operators = this.operatorKeyProvider.getAll().stream()
                .filter(c -> !c.getName().equals(name))
                .sorted((a, b) -> (int)(a.getCreated() - b.getCreated()))
                .collect(Collectors.toList());

        this.uploadAfterDelete(existingOperator.get(), operators);
    }

    private void runDelByKey(String key) throws Exception {
        Optional<OperatorKey> existingOperator = this.operatorKeyProvider.getAll()
                .stream().filter(c -> c.getKey().equals(key))
                .findFirst();
        if (!existingOperator.isPresent()) {
            throw new IllegalArgumentException("key: " + key + " not found");
        }

        List<OperatorKey> operators = this.operatorKeyProvider.getAll().stream()
                .filter(c -> !c.getKey().equals(key))
                .sorted((a, b) -> (int)(a.getCreated() - b.getCreated()))
                .collect(Collectors.toList());

        this.uploadAfterDelete(existingOperator.get(), operators);
    }

    private void runList() {
        Collection<OperatorKey> collection = this.operatorKeyProvider.getAll();
        for (OperatorKey c : collection) {
            if (this.isVerbose) {
                System.out.format("name: %s, key: %s, protocol: %s\n", c.getName(), c.getKey(), c.getProtocol());
            } else {
                System.out.format("name: %s, protocol: %s\n", c.getName(), c.getProtocol());
            }
        }
        System.out.println("Total " + collection.size() + " operator keys in the config");
    }

    private void runRollback() throws Exception {
        final ICloudStorage uploadStorage;
        if (this.isYes) {
            System.out.println("WARNING: uploading to cloud storage, which is potentially DESTRUCTIVE");
            uploadStorage = this.operatorKeyCloudStorage;
        } else {
            System.out.println("WARNING: uploading to dry-run mock storage, specify -yes to do actual upload");
            uploadStorage = new DryRunStorageMock(this.isVerbose);
        }

        this.bumpUpVersionAndRollback(uploadStorage, this.operatorKeyProvider);
        System.out.println("Rollback config uploaded");
    }

    private void uploadAfterDelete(OperatorKey operatorKey, Collection<OperatorKey> operators) throws Exception {
        Path newMetadataFile = Files.createTempFile("operators-metadata", ".json");
        Path newOperatorsFile = Files.createTempFile("operators", ".json");
        RotatingOperatorKeyProvider newOperatorKeyProvider = this.createLocalProvider(
                this.operatorKeyProvider.getMetadata(), operators, newMetadataFile, newOperatorsFile);

        int errors = this.verifyProviders(newOperatorKeyProvider, operatorKeyProvider);
        OperatorKey deletingOperator = newOperatorKeyProvider.getOperatorKey(operatorKey.getKey());
        if (deletingOperator != null) {
            System.err.println("Error: key is not deleted as expected " + operatorKey.getName());
            System.err.println(onelineJsonWriter.writeValueAsString(deletingOperator));
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
            uploadStorage = this.operatorKeyCloudStorage;
        } else {
            System.out.println("WARNING: uploading to dry-run mock storage, specify -yes to do actual upload");
            uploadStorage = new DryRunStorageMock(this.isVerbose);
        }

        this.bumpUpVersionAndUpload(uploadStorage, this.operatorKeyProvider, operators);
        System.out.println("New config uploaded");
    }

    private void bumpUpVersionAndRollback(ICloudStorage uploadStorage, RotatingOperatorKeyProvider provider)
            throws Exception {
        long generated = Instant.now().getEpochSecond();

        JsonObject metadata = provider.getMetadata();
        // bump up metadata version
        metadata.put("version", metadata.getLong("version") + 1);
        metadata.put("generated", generated);

        // get location to upload
        String location = metadata.getJsonObject("operators").getString("location");
        String backup = location + ".bak";

        // check if backup exists
        if (this.operatorKeyCloudStorage.list(backup).size() == 0) {
            throw new IllegalArgumentException("Unable to locate backup file to revert to: " + backup);
        }

        // crate local temp for old operators
        Path localTemp = Files.createTempFile("operators-old", ".json");
        Files.copy(uploadStorage.download(location), localTemp, StandardCopyOption.REPLACE_EXISTING);

        // crate local temp for backup operators
        Path localBackup = Files.createTempFile("operators-bak", ".json");
        Files.copy(uploadStorage.download(backup), localBackup, StandardCopyOption.REPLACE_EXISTING);

        // make backups
        uploadStorage.upload(localTemp.toString(), location + ".bak");
        uploadStorage.upload(localTemp.toString(), location + "." + String.valueOf(generated) + ".bak");

        // generate new metadata
        Path newMetadataFile = Files.createTempFile("operators-metadata", ".json");
        byte[] mdBytes = Json.encodePrettily(metadata).getBytes(StandardCharsets.UTF_8);
        Files.write(newMetadataFile, mdBytes, StandardOpenOption.CREATE);

        // upload new operators
        uploadStorage.upload(localBackup.toString(), location);

        // upload new metadata
        uploadStorage.upload(newMetadataFile.toString(), provider.getMetadataPath());
    }
}
