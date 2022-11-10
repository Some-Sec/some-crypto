package com.somesec.crypto.config;

/**
 * Cryptography constants that will be used as the default parameters in Encryption/Decryption operations if no arguments are provided.
 */
public enum DefaultConfig {
    /**
     * RSA Algorithm Name
     */
    RSA_ALGORITHM_NAME("RSA"),
    /**
     * ECDSA Algorithm Name
     */
    ECDSA_ALGORITHM_NAME("ECDSA"),
    /**
     * AES Algorithm Name
     */
    AES_ALGORITHM_NAME("AES"),
    /**
     * AES Cipher Name
     */
    AES_CIPHER_NAME("AES/GCM/NoPadding"),
    /**
     * AES GCM Nonce Length
     */
    AES_GCM_NONCE_LENGTH(12),
    /**
     * AES GCM Authentication Tag length
     */
    AES_GCM_TAG_LENGTH_BYTE(16),
    /**
     * PBKDF2 Key Factory
     */
    KEY_PBKDF2_FACTORY("PBKDF2WithHmacSHA256"),
    /**
     * Default Symmetric Key Algorithm
     */
    SYMMETRIC_KEY_ALGORITHM(AES_ALGORITHM_NAME.value),
    /**
     * Default Iterations for PBKDF2
     */
    PBKDF2_ITERATION(65536),
    /**
     * Default Symmetric Key Size
     */
    SYMMETRIC_KEY_SIZE(256),
    /**
     * NON-Prod Salt
     */
    SALT(
            new byte[]{(byte) 0xDA, (byte) 0xAC, 0x3E, 0x10, 0x55, (byte) 0xB5, (byte) 0xF1, 0x3A, 0x53, (byte) 0xE4, 0x71, (byte) 0xA8, 0x77, 0x78, (byte) 0x8E,
                    0x0A, (byte) 0x89, (byte) 0xAE, (byte) 0x96, 0x5F, 0x19, 0x5D, 0x53, 0x62, 0x58, (byte) 0x82, 0x2C, 0x09, (byte) 0xAD, 0x6E, 0x15, (byte) 0xD4}),
    /**
     * Default ECDSA Curve
     */
    ECDSA_CURVE_NAME("secp384r1"),
    /**
     * Default RSA Key Size
     */
    RSA_KEY_SIZE(2048),
    /**
     * How many bits per byte
     */
    BIT_IN_A_BYTE(8),
    /**
     * How many bytes in a megabyte
     */
    MEGA_BYTE(1024 * 1024);

    private final Object value;

    DefaultConfig(Object value) {
        this.value = value;
    }

    /**
     * Returns the configs containing value casted to the expected type
     *
     * @param <T> The type to be casted to
     * @return the default configuration
     */
    public <T> T getValue() {
        return (T) this.value;
    }

}