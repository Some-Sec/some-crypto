package com.somesec.crypto.decrypt;

import java.security.Key;

/**
 * Decryption interface used in all other sec-channel components. Default operations do not need usual parameters for decryption and will use default values of
 * the implementation.
 */
public interface DecryptionService {

    String decrypt(String cypheredText, Key key);

    byte[] decrypt(byte[] cypheredBytes, Key key);

}
