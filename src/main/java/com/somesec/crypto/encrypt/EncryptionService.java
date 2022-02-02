package com.somesec.crypto.encrypt;

import java.security.Key;

/**
 * Encryption interface used in all other sec-channel components. Default operations do not need usual parameters for encryption and will use default values of
 * the implementation.
 */
public interface EncryptionService {

    String encrypt(String plaintext, Key key);

    byte[] encrypt(byte[] plaintextBytes, Key key);

}
