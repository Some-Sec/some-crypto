package com.somesec.crypto.encrypt;

import com.somesec.crypto.decrypt.DecryptionService;

import java.security.Key;

/**
 * Encryption interface used in all other some-sec components. Default operations do not need usual parameters for encryption and will use default values of
 * the implementation.
 */
public interface EncryptionService {
    /**
     * Encrypts a plaintext, this really only takes the UTF-8 byte representation of that string and pipes it into {@link EncryptionService#encrypt(byte[], Key)}
     * @param plaintext the payload to be encrypted
     * @param key the encryption key, either symmetric or asymmetric
     * @return the cypher text
     */
    String encrypt(String plaintext, Key key);

    /**
     * Encrypts your byte[] payload with some sane defaults based on your Key type
     * @param plaintextBytes payload to be encrypted
     * @param key the encryption key, either symmetric or asymmetric
     * @return the cyphered payload
     */
    byte[] encrypt(byte[] plaintextBytes, Key key);

}
