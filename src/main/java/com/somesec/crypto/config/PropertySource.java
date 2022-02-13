package com.somesec.crypto.config;


/**
 * Interface to be implemented by your application.
 * This is needed to pass in specific configuration properties, such as the SALT to be used in PBKDF2 Key derivation.
 */
public interface PropertySource {

    /**
     * Returns the property value for the key passed in.
     * @param key to look up property
     * @param <T> The type expected for configuration
     * @return null if no value can be found, otherwise the property value behind the key.
     */
    <T> T getProperty(final String key);

    /**
     * Returns the property value for the key passed in.
     * @param key to look up property
     * @param targetType target class
     * @param <T> The type expected for configuration
     * @return null if no value can be found, otherwise the property value behind the key.
     */
    <T> T getProperty(final String key, final Class<T> targetType);
}
