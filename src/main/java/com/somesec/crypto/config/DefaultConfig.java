package com.somesec.crypto.config;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;

/**
 * Cryptography constants that will be used as the default parameters in Encryption/Decryption operations if no arguments are provided.
 */
public enum DefaultConfig  {
    RSA_ALGORITHM_NAME("RSA"),
    ECDSA_ALGORITHM_NAME("ECDSA"),
    AES_ALGORITHM_NAME("AES"),
    AES_CIPHER_NAME("AES/GCM/NoPadding"),
    AES_GCM_NONCE_LENGTH(12),
    AES_GCM_TAG_LENGTH_BYTE(16),
    KEY_PBKDF2_FACTORY("PBKDF2WithHmacSHA256"),
    SYMMETRIC_KEY_ALGORITHM(AES_ALGORITHM_NAME.value),
    PBKDF2_ITERATION(65536),
    SYMMETRIC_KEY_SIZE(256),
    SALT(
            new byte[]{(byte) 0xDA, (byte) 0xAC, 0x3E, 0x10, 0x55, (byte) 0xB5, (byte) 0xF1, 0x3A, 0x53, (byte) 0xE4, 0x71, (byte) 0xA8, 0x77, 0x78, (byte) 0x8E,
                    0x0A, (byte) 0x89, (byte) 0xAE, (byte) 0x96, 0x5F, 0x19, 0x5D, 0x53, 0x62, 0x58, (byte) 0x82, 0x2C, 0x09, (byte) 0xAD, 0x6E, 0x15, (byte) 0xD4}),
    ECDSA_CURVE_NAME("prime192v1"),
    RSA_KEY_SIZE(2048),
    BIT_IN_A_BYTE(8),
    TOKEN_ALGORITHM(JWEAlgorithm.RSA_OAEP_256),
    TOKEN_ENCRYPTION_METHOD(EncryptionMethod.A256GCM);

    private final Object value;

    DefaultConfig(Object value) {
        this.value = value;
    }


    public <T> T getValue() {
        return (T) this.value;
    }

}