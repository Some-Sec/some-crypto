package com.somesec.crypto.decrypt;

import java.security.Key;

/**
 * Decryption interface used in all other sec-channel components. Default operations do not need usual parameters for decryption and will use default values of
 * the implementation.
 */
public interface DecryptionService {

    String symDecryptDefault(String cypheredText, Key key);

    byte[] symDecryptDefault(byte[] cypheredTextBytes, Key key);

}
