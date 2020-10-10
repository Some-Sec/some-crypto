package com.somesec.crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;

import lombok.Getter;

/**
 * Cryptography constants that will be used as the default parameters in Encryption/Decryption operations if no arguments are provided.
 */
@Getter
public enum CryptoConstantsEnum {
    RSA("RSA"),
    ECDSA("ECDSA"),
    AES("AES"),
    AES_CIPHER("AES/GCM/NoPadding"),
    AES_DEFAULT_GCM_NONCE_LENGTH(12),
    AES_DEFAULT_GCM_TAG_LENGTH(16),
    KEY_DEFAULT_HKDF_INFO("aes-key"),
    KEY_HKDF_DEFAULT_DIGEST(new SHA256Digest()),
    KEY_DEFAULT_PBKDF2_FACTORY("PBKDF2WithHmacSHA256"),
    KEY_DEFAULT_SYMMETRIC_KEY_ALGORITHM("AES"),
    KEY_DEFAULT_PBKDF2_ITERATION(65536),
    KEY_DEFAULT_AES_KEY_SIZE(256),
    KEY_DEFAULT_32_BYTE_SALT(
        new byte[]{(byte) 0xDA, (byte) 0xAC, 0x3E, 0x10, 0x55, (byte) 0xB5, (byte) 0xF1, 0x3A, 0x53, (byte) 0xE4, 0x71, (byte) 0xA8, 0x77, 0x78, (byte) 0x8E,
            0x0A, (byte) 0x89, (byte) 0xAE, (byte) 0x96, 0x5F, 0x19, 0x5D, 0x53, 0x62, 0x58, (byte) 0x82, 0x2C, 0x09, (byte) 0xAD, 0x6E, 0x15, (byte) 0xD4}),
    KEY_DEFAULT_ECDSA_CURVE_NAME("prime192v1"),
    KEY_DEFAULT_RSA_SIZE(2048),
    TOKEN_DEFAULT_ALGORITHM(JWEAlgorithm.RSA_OAEP_256),
    TOKEN_DEFAULT_ENCRYPTION_METHOD(EncryptionMethod.A256GCM);

    private Object value;

    CryptoConstantsEnum(Object value) {
        this.value = value;
    }

}