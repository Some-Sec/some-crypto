package com.somesec.crypto.config;

/**
 * Interface to declare a configuration property resolver. This will lookup configuration values from a property source.
 * If it can not find a value it will lookup the value in the {@link DefaultConfig}
 */
public interface ConfigurationResolver {

    /**
     * Finds the configuration associated to a key in the property source attached to this.
     *
     * @param key associated to configuration property
     * @param <T> the type expected to be returned
     * @return null if no property associated to key
     */
    <T> T getConfig(String key);

    /**
     * Finds the configuration associated to a key in the property source attached to this.
     * Furthermore this function will call {@link Enum#name()} and use the name of the enum as a key to pass it into {@link ConfigurationResolver#getConfig(String)}
     *
     * @param key associated to configuration property
     * @param <T> the type expected to be returned
     * @return null if no property associated to key
     */
    <T> T getConfig(Enum<?> key);


}
