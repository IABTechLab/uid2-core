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

import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.uid2.shared.Const;
import com.uid2.shared.auth.EnclaveIdentifierProvider;
import com.uid2.shared.auth.Role;
import com.uid2.shared.cloud.*;
import com.uid2.shared.model.EnclaveIdentifier;
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
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

public class EnclaveIdTool {

    private final ObjectWriter onelineJsonWriter;
    private final ObjectWriter jsonWriter;
    private JsonObject config;
    private boolean isVerbose = false;
    private boolean isDryRun = true;
    private final EnclaveIdentifierProvider enclaveIdProvider;
    private final ICloudStorage operatorIdCloudStorage;

    EnclaveIdTool(JsonObject config) throws Exception {
        this.config = config;
        if(config.getString("core_s3_bucket") == null) {
            this.operatorIdCloudStorage = new EmbeddedResourceStorage(com.uid2.core.Main.class);
        } else {
            this.operatorIdCloudStorage = CloudUtils.createStorage(config.getString("core_s3_bucket"), config);
        }
        String metadataPath = config.getString("enclaves_metadata_path");
        this.enclaveIdProvider = new EnclaveIdentifierProvider(operatorIdCloudStorage, metadataPath);
        this.enclaveIdProvider.loadContent(this.enclaveIdProvider.getMetadata());
        
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
        } else {
            System.out.format("Running LOCAL DEBUG mode, config: %s\n", Const.Config.LOCAL_CONFIG_PATH);
            System.setProperty(Const.Config.VERTX_CONFIG_PATH_PROP, Const.Config.LOCAL_CONFIG_PATH);
        }

        VertxUtils.createConfigRetriever(vertx).getConfig(ar -> {
            try {
                EnclaveIdTool tool = new EnclaveIdTool(ar.result());
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

    private void run(String[] args) throws Exception {
        CommandLine cli = parseArgs(args);
        this.isVerbose = cli.isFlagEnabled("verbose");
        if(this.isVerbose) {
            System.out.println("VERBOSE on");
        }
        this.isDryRun = !cli.isFlagEnabled("yes");
        if(!this.isDryRun) {
            System.out.println("Pre-confirmed to proceed with potentially DESTRUCTIVE operation");
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
            String protocol = cli.getOptionValue("protocol");
            String identifier = cli.getOptionValue("identifier");
            checkOptionExistence(protocol, command, "protocol");
            checkOptionExistence(identifier, command, "identifier");
            add(name, protocol, identifier);
        } else if ("del".equals(command)) {
            String protocol = cli.getOptionValue("protocol");
            String identifier = cli.getOptionValue("identifier");
            checkOptionExistence(protocol, command, "protocol");
            checkOptionExistence(identifier, command, "identifier");
            remove(protocol, identifier);
        } else if ("list".equals(command)) {
            list();
        } else if ("rollback".equals(command)) {
            rollback();
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
                .setDescription("find or specify identifier by the name")
                .setRequired(false))
            .addOption(new Option()
                .setLongName("protocol")
                .setShortName("proto")
                .setDescription("filter identifier by the protocol")
                .setRequired(false))
            .addOption(new Option()
                .setLongName("identifier")
                .setShortName("id")
                .setDescription("filter identifier by the identifier")
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

    private void add(String name, String protocol, String identifier) throws Exception {
        Collection<EnclaveIdentifier> identifiers = enclaveIdProvider.getAll();
        List<EnclaveIdentifier> newIdentifiers = new ArrayList<>(identifiers);
        boolean isChanged;
        if(identifiers.stream().anyMatch(x -> x.getProtocol().equals(identifier) && x.getIdentifier().equals(identifier))) {
            isChanged = false;
        } else {
            isChanged = true;
            newIdentifiers.add(new EnclaveIdentifier(name, protocol, identifier, Instant.now().getEpochSecond()));
            newIdentifiers = newIdentifiers.stream().sorted((a, b) -> (int)(a.getCreated() - b.getCreated())).collect(Collectors.toList());
        }

        if(isChanged) {
            this.update(getUploadStorage(), newIdentifiers);
            System.out.println("Identifier added - {name=" + name +", protocol=" + protocol + ", identifier=" + identifier + "}");
        } else {
            System.out.println("No changes were made - supplied (protocol, id) pair exists");
        }
    }

    private void remove(String protocol, String identifier) throws Exception {
        Collection<EnclaveIdentifier> identifiers = enclaveIdProvider.getAll();
        List<EnclaveIdentifier> newIdentifiers = new ArrayList<>();
        boolean isChanged = false;
        for(EnclaveIdentifier id : identifiers) {
            if(id.getProtocol().equals(protocol) && id.getIdentifier().equals(identifier)) {
                isChanged = true;
            } else {
                newIdentifiers.add(id);
            }
        }

        if(isChanged) {
            System.out.println("Identifier removed - " + newIdentifiers.size() + " ids remain");
            update(getUploadStorage(), newIdentifiers);
        } else {
            System.out.println("No changes were made - supplied (protocol, id) pair is not present");
        }
    }

    private void list() {
        Collection<EnclaveIdentifier> identifiers = enclaveIdProvider.getAll();
        for(EnclaveIdentifier id : identifiers) {
            System.out.println("{name: " + id.getName() + ", protocol: " + id.getProtocol() + ", id: " + id.getIdentifier() + "}");
        }
    }

    private void rollback() throws Exception {
        // copy to avoid changing provider's state
        JsonObject metadata = this.enclaveIdProvider.getMetadata().copy();
        String location = metadata.getJsonObject("enclaves").getString("location");
        String cloudBackupFilePath = location + ".bak";
        if(this.operatorIdCloudStorage.list(cloudBackupFilePath).size() == 0) {
            System.out.println("Unable to locate backup file, abort");
            return;
        }

        metadata.getJsonObject("enclaves").put("location", cloudBackupFilePath);
        this.enclaveIdProvider.loadContent(metadata);
        Collection<EnclaveIdentifier> backupContent = this.enclaveIdProvider.getAll();

        update(getUploadStorage(), backupContent);
    }

    private ICloudStorage getUploadStorage() {
        if(isDryRun) {
            System.out.println("WARNING: uploading to dry-run mock storage, specify -yes to do actual upload");
            return new DryRunStorageMock(this.isVerbose);
        } else {
            System.out.println("WARNING: uploading to cloud storage, which is potentially DESTRUCTIVE");
            return this.operatorIdCloudStorage;
        }
    }

    private void update(ICloudStorage cloudStorage, Collection<EnclaveIdentifier> identifiers) throws Exception {
        long generated = Instant.now().getEpochSecond();
        JsonObject metadata = this.enclaveIdProvider.getMetadata();

        metadata.put("version", metadata.getLong("version") + 1);
        metadata.put("generated", generated);
        String location = getStorageLocation(metadata);

        // store old enclaves
        Path localTemp = Files.createTempFile("enclaves-old", ".json");
        Files.copy(cloudStorage.download(location), localTemp, StandardCopyOption.REPLACE_EXISTING);

        // make backups
        cloudStorage.upload(localTemp.toString(), location + ".bak");
        cloudStorage.upload(localTemp.toString(), location + "." + String.valueOf(generated) + ".bak");

        // generate new clients
        Path newFile = Files.createTempFile("enclaves", ".json");
        byte[] contentBytes = jsonWriter.writeValueAsString(identifiers).getBytes(StandardCharsets.UTF_8);
        Files.write(newFile, contentBytes, StandardOpenOption.CREATE);

        // generate new metadata
        Path newMetadataFile = Files.createTempFile("enclaves-metadata", ".json");
        byte[] mdBytes = Json.encodePrettily(metadata).getBytes(StandardCharsets.UTF_8);
        Files.write(newMetadataFile, mdBytes, StandardOpenOption.CREATE);

        // upload new clients
        cloudStorage.upload(newFile.toString(), location);
        cloudStorage.upload(newMetadataFile.toString(), enclaveIdProvider.getMetadataPath());
    }

    private void checkOptionExistence(String val, String command, String option) throws Exception {
        if (val == null) {
            throw new Exception("option -" + option + " is required for command " + command);
        }
    }

    private String getStorageLocation(JsonObject metadata) {
        return metadata.getJsonObject("enclaves").getString("location");
    }
}
