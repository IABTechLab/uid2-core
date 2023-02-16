package com.uid2.core.model;

public class SecretStore extends ConfigStore {
    public static final SecretStore Global = new SecretStore();

    @Override
    public String getPrintable(String key) {
        return "{" + key + ":********}";
    }
}
