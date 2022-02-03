package com.somesec.crypto.decrypt;

import java.security.Key;

/**
 * Decryption interface used in all other some-sec components.
 * Default operations do not need usual parameters for decryption and will use sane default values of
 * the implementation.
 */
public interface DecryptionService {
    /**
     * Decrypts a cyphertext, this really only takes the UTF-8 byte representation of that string and pipes it into {@link DecryptionService#decrypt(byte[], Key)}
     *
     * @param cypheredText the ciphered string, this should not be encoded in any way
     * @param key          the secret key to decipher the text
     * @return the plain text string in UTF-8
     */
    String decrypt(String cypheredText, Key key);

    /**
     * This is a  simplified abstraction of a deciphering operation. Based on your {@link Key} type it will use the default algorithm for decryption
     * for example an instance of {@link javax.crypto.SecretKey} will lead to an attempt to decrypt a cipher made with AES-256
     *
     * @param cypheredBytes the ciphered payload, this should not be encoded in any way
     * @param key           the secret key to decipher the payload
     * @return the decrypted bytes
     */
    byte[] decrypt(byte[] cypheredBytes, Key key);

}
