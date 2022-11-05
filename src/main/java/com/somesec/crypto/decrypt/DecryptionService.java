package com.somesec.crypto.decrypt;

import java.io.InputStream;
import java.io.OutputStream;
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

    /**
     * Decrypts the cipherText received from the InputStream and writes it into the OutputStream
     * This operation is recommended for large files as it should be, depending on the stream implementation, less memory intensive.
     *
     * It is expected that the streams will be closed once this method has finished
     * @param cipherText the data stream delivering the data to be decrypted
     * @param plainText the stream delivering the plainText
     * @param key     the encryption key, either symmetric or asymmetric
     */
    void decrypt(InputStream cipherText, OutputStream plainText, Key key);

}
