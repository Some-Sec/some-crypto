package com.somesec.crypto.config;

public interface ConfigurationResolver {


    <T> T getConfig(String key);

    <T> T getConfig(Enum<?> key);


}
