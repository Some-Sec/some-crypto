package com.somesec.crypto.encrypt;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;

/**
 * Encryption interface used in all other some-sec components. Default operations do not need usual parameters for encryption and will use default values of
 * the implementation.
 */
public interface EncryptionService {
    /**
     * Encrypts a plaintext, this really only takes the UTF-8 byte representation of that string and pipes it into {@link EncryptionService#encrypt(byte[], Key)}
     *
     * @param plaintext the payload to be encrypted
     * @param key       the encryption key, either symmetric or asymmetric
     * @return the cypher text
     */
    String encrypt(String plaintext, Key key);

    /**
     * Encrypts your byte[] payload with some sane defaults based on your Key type
     *
     * @param plaintextBytes payload to be encrypted
     * @param key            the encryption key, either symmetric or asymmetric
     * @return the cyphered payload
     */
    byte[] encrypt(byte[] plaintextBytes, Key key);


    /**
     * Encrypts the plainText received from the InputStream, encrypts it and writes them into the OutputStream
     * This operation is recommended for large files as it should be, depending on the stream implementation, less memory intensive.
     *
     * It is expected that the streams will be closed once this method has finished
     * @param plainText the data stream delivering the data to be encrypted
     * @param cipherText the stream delivering the ciphertext
     * @param key     the encryption key, either symmetric or asymmetric
     */
    void encrypt(InputStream plainText, OutputStream cipherText, Key key);


}
