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

import com.amazonaws.services.s3.model.Encryption;
import com.uid2.core.service.KeyAclMetadataProvider;
import com.uid2.shared.Const;
import com.uid2.shared.auth.EncryptionKeyAcl;
import com.uid2.shared.auth.RotatingKeyAclProvider;
import com.uid2.shared.cloud.CloudUtils;
import com.uid2.shared.cloud.DryRunStorageMock;
import com.uid2.shared.cloud.ICloudStorage;
import com.uid2.shared.model.EncryptionKey;
import com.uid2.shared.store.RotatingKeyStore;
import com.uid2.shared.vertx.VertxUtils;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.core.cli.*;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class EncryptionKeyTool {
    private JsonObject config;
    private boolean isVerbose = false;
    private boolean isYes = false;
    private final ICloudStorage cloudStorage;
    private final RotatingKeyStore keyStore;
    private final RotatingKeyAclProvider keyAclProvider;

    EncryptionKeyTool(JsonObject config) throws Exception {
        this.config = config;
        this.cloudStorage = CloudUtils.createStorage(config.getString("core_s3_bucket"), config);
        String keyMetadataPath = config.getString(Const.Config.KeysMetadataPathProp);
        String aclMetadataPath = config.getString(Const.Config.KeysAclMetadataPathProp);
        this.keyStore = new RotatingKeyStore(cloudStorage, keyMetadataPath);
        this.keyAclProvider = new RotatingKeyAclProvider(cloudStorage, aclMetadataPath);
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

        JsonObject config = VertxUtils.getJsonConfig(vertx);
        try {
            EncryptionKeyTool tool = new EncryptionKeyTool(config);
            tool.run(args);
        } catch (Exception e) {
            e.printStackTrace();
            vertx.close();
            System.exit(1);
        }
        vertx.close();
        System.exit(0); // keeps "mvn exec" happy
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
        supportedCommands.add("whitelist");
        supportedCommands.add("blacklist");
        supportedCommands.add("listacl");
        supportedCommands.add("showacl");
        supportedCommands.add("delacl");
        supportedCommands.add("resetacl");

        String command = cli.getArgumentValue("command");
        if (!supportedCommands.contains(command)) {
            System.err.println("Unknown command: " + command);
        } else if ("list".equals(command)) {
            Integer ownerSiteId = cli.getOptionValue("site");
            runListKeys(ownerSiteId);
        } else if ("add".equals(command)) {
            Integer ownerSiteId = cli.getOptionValue("site");
            if(ownerSiteId == null) {
                System.err.println("Must specify owner site id");
                System.exit(1);
            }
            runAddKey(ownerSiteId);
        } else if ("del".equals(command)) {
            Integer keyId = cli.getOptionValue("id");
            String keySecret = cli.getOptionValue("key");
            if(keyId != null) {
                runDelKey(key -> key.getId() == keyId);
            } else if (keySecret != null) {
                byte[] keySecretBytes = Base64.getDecoder().decode(keySecret);
                runDelKey(key -> Arrays.equals(key.getKeyBytes(), keySecretBytes));
            } else {
                System.err.println("Must specify key id or key secret");
                System.exit(1);
            }
        } else if ("listacl".equals(command)) {
            runListAcl();
        } else if ("showacl".equals(command)) {
            Integer ownerSiteId = cli.getOptionValue("site");
            if(ownerSiteId == null) {
                System.err.println("Must specify owner site id");
                System.exit(1);
            }
            runShowAcl(ownerSiteId);
        } else if ("whitelist".equals(command)) {
            Integer ownerSiteId = cli.getOptionValue("site");
            Integer clientSiteId = cli.getOptionValue("client");
            if(ownerSiteId == null) {
                System.err.println("Must specify whitelist owner site id");
                System.exit(1);
            }

            // Not specifying a clientSiteId allows one to create an empty whitelist

            runAddAclEntry(true, ownerSiteId, clientSiteId);
        } else if ("blacklist".equals(command)) {
            Integer ownerSiteId = cli.getOptionValue("site");
            Integer clientSiteId = cli.getOptionValue("client");
            if(ownerSiteId == null || clientSiteId == null) {
                System.err.println("Must specify owner site id and blacklisted client site id");
                System.exit(1);
            }
            runAddAclEntry(false, ownerSiteId, clientSiteId);
        } else if ("delacl".equals(command)) {
            Integer ownerSiteId = cli.getOptionValue("site");
            Integer clientSiteId = cli.getOptionValue("client");
            if(ownerSiteId == null || clientSiteId == null) {
                System.err.println("Must specify owner site id and blacklisted client site id");
                System.exit(1);
            }
            runDelAclEntry(ownerSiteId, clientSiteId);
        } else if ("resetacl".equals(command)) {
            Integer ownerSiteId = cli.getOptionValue("site");
            if(ownerSiteId == null) {
                System.err.println("Must specify owner site id");
                System.exit(1);
            }
            runResetAcl(ownerSiteId);
        }
    }

    private CommandLine parseArgs(String[] args) {
        final CLI cli = CLI.create("encryption-key-tool")
                .setSummary("A tool for managing encryption keys for uid2-core")
                .addArgument(new Argument()
                        .setArgName("command")
                        .setDescription("command to run can be one of: list, add, del, whitelist, blacklist, listacl, showacl, delacl, resetacl")
                        .setRequired(true))
                .addOption(new TypedOption<Integer>()
                        .setLongName("site")
                        .setShortName("s")
                        .setDescription("specify site id of the encryption keys owner")
                        .setType(Integer.class)
                        .setRequired(false))
                .addOption(new TypedOption<Integer>()
                        .setLongName("client")
                        .setShortName("c")
                        .setDescription("specify site id of the client wishing to access encryption keys")
                        .setType(Integer.class)
                        .setRequired(false))
                .addOption(new TypedOption<Integer>()
                        .setLongName("id")
                        .setShortName("i")
                        .setDescription("find key by the specified id")
                        .setType(Integer.class)
                        .setRequired(false))
                .addOption(new Option()
                        .setLongName("key")
                        .setShortName("k")
                        .setDescription("find key by the specified base64-encoded key bytes (secret)")
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

        if(args.length < 1) {
            StringBuilder usage = new StringBuilder();
            cli.usage(usage);
            System.out.println(usage.toString());
            System.exit(0);
        }

        return cli.parse(Arrays.asList(args));
    }

    private void runListKeys(Integer ownerSiteId) throws Exception {
        keyStore.loadContent();

        List<EncryptionKey> keys = keyStore.getSnapshot().getActiveKeySet();
        if(ownerSiteId != null) {
            keys = keys.stream().filter(k -> k.getSiteId() == ownerSiteId).collect(Collectors.toList());
        }

        for(EncryptionKey key : keys) {
            System.out.println(String.format("{id: %d, site: %d, created: %s, expires: %s%s}",
                    key.getId(), key.getSiteId(), key.getCreated(), key.getExpires(),
                    (isVerbose ? (", secret: " + Base64.getEncoder().encodeToString(key.getKeyBytes())) : "")));
        }
    }

    private void runAddKey(int ownerSiteId) throws Exception {
        keyStore.loadContent();
        List<EncryptionKey> keys = keyStore.getSnapshot().getActiveKeySet();

        int maxKeyId = keys.isEmpty() ? 0 : Collections.max(keys, Comparator.comparing(k -> ((EncryptionKey)k).getId())).getId();
        final Integer metadataMaxKeyId = keyStore.getMetadata().getInteger("max_key_id");
        if(metadataMaxKeyId != null) {
            // allows to avoid re-using deleted keys' ids
            maxKeyId = Integer.max(maxKeyId, metadataMaxKeyId);
        }
        if(maxKeyId == Integer.MAX_VALUE) {
            throw new ArithmeticException("Cannot generate a new key id: max key id reached");
        }
        final int keyId = maxKeyId + 1;

        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);

        final Instant created = Instant.now();
        final int activeInDays = 1;
        final int expiryInDays = 10 * 365; // ~10 years
        final Instant activates = created.plus(activeInDays, ChronoUnit.DAYS);
        final Instant expires = created.plus(expiryInDays, ChronoUnit.DAYS);
        EncryptionKey key = new EncryptionKey(keyId, bytes, created, activates, expires, ownerSiteId);
        keys.add(key);

        update(getUploadStorage(), keys, keyId);
        System.out.println("Updated encryption keys");
        System.out.println("New key id=" + keyId + " for site " + ownerSiteId + " is (base64-encoded): " + Base64.getEncoder().encodeToString(bytes));
    }

    private void runDelKey(Predicate<EncryptionKey> keyPredicate) throws Exception {
        keyStore.loadContent();
        List<EncryptionKey> keys = keyStore.getSnapshot().getActiveKeySet();
        List<EncryptionKey> updatedKeys = keys.stream().filter(keyPredicate.negate()).collect(Collectors.toList());

        if(updatedKeys.size() >= keys.size()) {
            System.out.println("Cannot find the specified key");
            System.err.println("No changes made");
            return;
        }

        update(getUploadStorage(), keys, null);
        System.out.println("Updated encryption keys");
    }

    private void runListAcl() throws Exception {
        keyAclProvider.loadContent();
        Map<Integer, EncryptionKeyAcl> acls = keyAclProvider.getSnapshot().getAllAcls();
        for(Map.Entry<Integer, EncryptionKeyAcl> aclEntry : acls.entrySet()) {
            int siteId = aclEntry.getKey();
            EncryptionKeyAcl acl = aclEntry.getValue();
            System.out.println("{siteId: " + siteId + ", " + (acl.getIsWhitelist() ? "whitelist" : "blacklist") + ": [" + acl.getAccessList().size() + " entries]}");
        }
    }

    private void runShowAcl(int ownerSiteId) throws Exception {
        keyAclProvider.loadContent();
        Map<Integer, EncryptionKeyAcl> acls = keyAclProvider.getSnapshot().getAllAcls();
        EncryptionKeyAcl acl = acls.get(ownerSiteId);
        if(acl == null) {
            System.out.println("Site id " + ownerSiteId + " does not have an ACL.");
        } else {
            System.out.println("{siteId: " + ownerSiteId + ", " + (acl.getIsWhitelist() ? "whitelist" : "blacklist") + ": ["
                + String.join(",", acl.getAccessList().stream().map(s -> s.toString()).collect(Collectors.toList()))
                + "]}");
        }
    }

    private void runAddAclEntry(boolean isWhitelist, int ownerSiteId, Integer clientSiteId) throws Exception {
        if(clientSiteId != null && ownerSiteId == clientSiteId) {
            System.err.println("Site cannot appear whitelisted/blacklisted in its own ACL, owner and client site ids must be different");
            System.exit(1);
        }

        keyAclProvider.loadContent();
        Map<Integer, EncryptionKeyAcl> acls = keyAclProvider.getSnapshot().getAllAcls();
        EncryptionKeyAcl acl = acls.get(ownerSiteId);
        if(acl == null)
        {
            acl = new EncryptionKeyAcl(isWhitelist, new HashSet<>());
            acls.put(ownerSiteId, acl);
            if(clientSiteId != null) {
                acl.getAccessList().add(clientSiteId);
            }
        } else if(acl.getIsWhitelist() != isWhitelist) {
            System.err.println("Site id " + ownerSiteId + " uses a different type of access list (blacklist vs whitelist)");
            System.exit(1);
        } else if(clientSiteId == null) {
            System.err.println("Site id " + ownerSiteId + " already has an empty access list (blacklist or whitelist)");
            System.err.println("No changes made");
            return;
        } else if(acl.getAccessList().contains(clientSiteId)) {
            System.err.println("Client site id " + clientSiteId + " has already been whitelisted/blacklisted by site id " + ownerSiteId);
            System.err.println("No changes made");
            return;
        } else {
            acl.getAccessList().add(clientSiteId);
        }

        update(getUploadStorage(), acls);
        System.out.println("Updated access control list for site " + ownerSiteId);

        if(!isWhitelist) {
            System.out.println("Generating a new encryption key that the blacklisted site will not have access to");
            runAddKey(ownerSiteId);
        }
    }

    private void runDelAclEntry(int ownerSiteId, int clientSiteId) throws Exception {
        keyAclProvider.loadContent();
        Map<Integer, EncryptionKeyAcl> acls = keyAclProvider.getSnapshot().getAllAcls();
        EncryptionKeyAcl acl = acls.get(ownerSiteId);
        if(acl == null) {
            System.out.println("Site id " + ownerSiteId + " does not have an ACL");
            System.out.println("No changes made");
            return;
        } else if (!acl.getAccessList().contains((clientSiteId))) {
            System.out.println("Site id " + clientSiteId + " is not present in ACL for site " + ownerSiteId);
            System.out.println("No changes made");
            return;
        }

        acl.getAccessList().remove(clientSiteId);
        // Must not delete an empty list from acls: an empty whitelist is not the same as no whitelist

        update(getUploadStorage(), acls);
        System.out.println("Updated access control list for site " + ownerSiteId);

        if(acl.getIsWhitelist()) {
            System.out.println("Generating a new encryption key that the site removed from whitelist will not have access to");
            runAddKey(ownerSiteId);
        }
    }

    private void runResetAcl(int ownerSiteId) throws Exception {
        keyAclProvider.loadContent();
        Map<Integer, EncryptionKeyAcl> acls = keyAclProvider.getSnapshot().getAllAcls();
        EncryptionKeyAcl acl = acls.remove(ownerSiteId);
        if(acl == null) {
            System.out.println("Site id " + ownerSiteId + " does not have an ACL");
            System.out.println("No changes made");
            return;
        }

        update(getUploadStorage(), acls);
        System.out.println("Deleted access control list for site " + ownerSiteId);
    }

    private void update(ICloudStorage cloudStorage, List<EncryptionKey> keys, Integer newMaxKeyId) throws Exception {
        long generated = Instant.now().getEpochSecond();
        JsonObject metadata = this.keyStore.getMetadata();

        metadata.put("version", metadata.getLong("version") + 1);
        metadata.put("generated", generated);
        if(newMaxKeyId != null) {
            metadata.put("max_key_id", newMaxKeyId);
        }
        String location = metadata.getJsonObject("keys").getString("location");

        // store old keys
        Path localTemp = Files.createTempFile("keys-old", ".json");
        Files.copy(cloudStorage.download(location), localTemp, StandardCopyOption.REPLACE_EXISTING);

        // make backups
        cloudStorage.upload(localTemp.toString(), location + ".bak");
        cloudStorage.upload(localTemp.toString(), location + "." + String.valueOf(generated) + ".bak");

        // generate new keys
        Path newFile = Files.createTempFile("keys", ".json");
        JsonArray jsonKeys = new JsonArray();
        try(FileWriter writer = new FileWriter(newFile.toString()))
        {
            for(EncryptionKey key : keys) {
                JsonObject json = new JsonObject();
                json.put("id", key.getId());
                json.put("site_id", key.getSiteId());
                json.put("created", key.getCreated().getEpochSecond());
                json.put("activates", key.getActivates().getEpochSecond());
                json.put("expires", key.getExpires().getEpochSecond());
                json.put("secret", key.getKeyBytes());
                jsonKeys.add(json);
            }
        }
        byte[] contentBytes = jsonKeys.encodePrettily().getBytes(StandardCharsets.UTF_8);
        Files.write(newFile, contentBytes, StandardOpenOption.CREATE);

        // generate new metadata
        Path newMetadataFile = Files.createTempFile("keys-metadata", ".json");
        byte[] mdBytes = Json.encodePrettily(metadata).getBytes(StandardCharsets.UTF_8);
        Files.write(newMetadataFile, mdBytes, StandardOpenOption.CREATE);

        // upload new keys
        cloudStorage.upload(newFile.toString(), location);
        cloudStorage.upload(newMetadataFile.toString(), keyStore.getMetadataPath());
    }

    private void update(ICloudStorage cloudStorage, Map<Integer, EncryptionKeyAcl> acls) throws Exception {
        long generated = Instant.now().getEpochSecond();
        JsonObject metadata = this.keyAclProvider.getMetadata();

        metadata.put("version", metadata.getLong("version") + 1);
        metadata.put("generated", generated);
        String location = metadata.getJsonObject("keys_acl").getString("location");

        // store old acls
        Path localTemp = Files.createTempFile("keys_acl-old", ".json");
        Files.copy(cloudStorage.download(location), localTemp, StandardCopyOption.REPLACE_EXISTING);

        // make backups
        cloudStorage.upload(localTemp.toString(), location + ".bak");
        cloudStorage.upload(localTemp.toString(), location + "." + String.valueOf(generated) + ".bak");

        // generate new acls
        Path newFile = Files.createTempFile("keys_acl", ".json");
        JsonArray jsonAcls = new JsonArray();
        for(Map.Entry<Integer, EncryptionKeyAcl> acl : acls.entrySet()) {
            JsonObject jsonAcl = new JsonObject();
            jsonAcl.put("site_id", acl.getKey());
            jsonAcl.put((acl.getValue().getIsWhitelist() ? "whitelist" : "blacklist"),
                    new JsonArray(new ArrayList<>(acl.getValue().getAccessList())));
            jsonAcls.add(jsonAcl);
        }
        byte[] contentBytes = jsonAcls.encodePrettily().getBytes(StandardCharsets.UTF_8);
        Files.write(newFile, contentBytes, StandardOpenOption.CREATE);

        // generate new metadata
        Path newMetadataFile = Files.createTempFile("keys_acl-metadata", ".json");
        byte[] mdBytes = Json.encodePrettily(metadata).getBytes(StandardCharsets.UTF_8);
        Files.write(newMetadataFile, mdBytes, StandardOpenOption.CREATE);

        // upload new acls
        cloudStorage.upload(newFile.toString(), location);
        cloudStorage.upload(newMetadataFile.toString(), keyAclProvider.getMetadataPath());
    }

    private ICloudStorage getUploadStorage() {
        if(!isYes) {
            System.out.println("WARNING: uploading to dry-run mock storage, specify -yes to do actual upload");
            return new DryRunStorageMock(this.isVerbose);
        } else {
            System.out.println("WARNING: uploading to cloud storage, which is potentially DESTRUCTIVE");
            return this.cloudStorage;
        }
    }
}
