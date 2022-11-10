package com.somesec.crypto.encrypt;

import com.somesec.crypto.CryptographicOperation;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;

/**
 * A cryptographic operation dedicated for the encryption of data
 */
public interface EncryptionOperation extends CryptographicOperation {
    /**
     * Encrypts your byte[] payload with some sane defaults based on your Key type
     *
     * @param payload to be encrypted
     * @param key     the encryption key, either symmetric or asymmetric
     * @return the cyphered payload
     */
    byte[] encrypt(byte[] payload, Key key);

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
