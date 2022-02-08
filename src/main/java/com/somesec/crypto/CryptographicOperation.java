package com.somesec.crypto;

import com.somesec.crypto.constant.CryptographicType;

import java.security.Key;

/**
 * An operation that can be used to either encrypt, decrypt or sign a respective payload
 */
public interface CryptographicOperation {
    /**
     * The operation supported by the concrete implementation. This will be the concrete cryptographic operation such as
     * {@link com.somesec.crypto.encrypt.AESEncryption} or {@link com.somesec.crypto.decrypt.AESDecryption}
     * @return the concrete type of operation
     */
    CryptographicType getSupportedOperation();

    /**
     * The type of key needed to conclude the Cryptographic operation. For example {@link javax.crypto.SecretKey} in case of symmetric cryptography
     * @return the type of key for respective operation
     */
    Class<? extends Key> getKeyClass();

    /**
     * This will deliver the name of the algorithm for the respective implementation for example AES
     * @return
     */
    String getAlgorithmName();
}
