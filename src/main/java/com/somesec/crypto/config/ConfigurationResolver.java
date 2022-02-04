package com.somesec.crypto.config;

public interface ConfigurationResolver {


    <T> T getConfig(String key);

    default <T> T getConfig(Enum<?> key) {
        return this.getConfig(key.name());
    }


}
