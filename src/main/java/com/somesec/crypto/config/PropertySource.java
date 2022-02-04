package com.somesec.crypto.config;

public interface PropertySource {

    <T> T getProperty(final String key);
}
