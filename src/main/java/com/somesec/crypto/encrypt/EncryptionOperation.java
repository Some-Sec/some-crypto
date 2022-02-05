package com.somesec.crypto.encrypt;

import com.somesec.crypto.CryptographicOperation;

import java.security.Key;

public interface EncryptionOperation extends CryptographicOperation {
    /**
     * Encrypts your byte[] payload with some sane defaults based on your Key type
     *
     * @param payload to be encrypted
     * @param key            the encryption key, either symmetric or asymmetric
     * @return the cyphered payload
     */
    byte[] encrypt(byte[] payload, Key key);

}
