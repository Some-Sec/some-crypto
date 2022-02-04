package com.somesec.crypto.config;

import com.somesec.crypto.constant.MessagesCode;
import com.somesec.crypto.exception.CryptoOperationException;

import java.util.Arrays;

public class ConfigurationResolverImpl implements ConfigurationResolver {


    private final PropertySource propertySource;

    public ConfigurationResolverImpl() {
        propertySource = null;
    }

    public ConfigurationResolverImpl(final PropertySource propertySource) {
        this.propertySource = propertySource;
    }


    @Override
    public <T> T getConfig(final String key) {
        if (key == null) {
            throw new IllegalArgumentException(MessagesCode.ERROR_KEY_NOT_NULLABLE.getMessage());
        }
        final T property = getFromPropertiesSource(key);
        if (property != null) {
            return property;
        }

        return getValueFromDefaultConfig(key);
    }


    private <T> T getValueFromDefaultConfig(final String key) {
        return Arrays.stream(DefaultConfig.values())
                .filter(cryptoConstantsEnum -> cryptoConstantsEnum.name().equalsIgnoreCase(key))
                .findAny()
                .orElseThrow(() -> new CryptoOperationException(MessagesCode.ERROR_NO_CONFIGURATION_FOR_KEY,key)).getValue();
    }

    private <T> T getFromPropertiesSource(final String key) {
        if (propertySource == null) {
            return null;
        }
        return propertySource.getProperty(key);
    }


}
