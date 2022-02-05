package com.somesec.crypto.decrypt;

import com.somesec.crypto.CryptographicOperation;

import java.security.Key;

public interface DecryptionOperation extends CryptographicOperation {

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
