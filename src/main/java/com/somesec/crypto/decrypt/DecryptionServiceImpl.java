package com.somesec.crypto.decrypt;

import com.somesec.crypto.constant.CryptographicType;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.List;

/**
 * {@see DecryptionService}
 */
public class DecryptionServiceImpl implements DecryptionService {

    private final List<DecryptionOperation> cryptoOperations;

    /**
     * Create an instance able to handle the passed in decryption operations
     * @param cryptoOperations
     */
    public DecryptionServiceImpl(List<DecryptionOperation> cryptoOperations) {
        this.cryptoOperations = cryptoOperations;
    }


    @Override
    public String decrypt(String cypheredText, Key key) {
        return new String(this.decrypt(cypheredText.getBytes(StandardCharsets.UTF_8), key), StandardCharsets.UTF_8);
    }

    @Override
    public byte[] decrypt(byte[] cypheredBytes, Key key) {
        final DecryptionOperation decryptionOperation = findSupportedOperation(key);
        return decryptionOperation.decrypt(cypheredBytes, key);
    }

    @Override
    public void decrypt(InputStream cipherText, OutputStream plainText, Key key) {
        final DecryptionOperation decryptionOperation = findSupportedOperation(key);
        decryptionOperation.decrypt(cipherText, plainText, key);
    }

    /**
     * Determines which {@link DecryptionOperation} to use based on KeyType
     * @param key
     * @return A supported decryption Operation
     */
    // todo unit test
    protected DecryptionOperation findSupportedOperation(Key key) {

        return cryptoOperations
                .stream()
                .filter(cryptoOperation -> cryptoOperation.getSupportedOperation() == CryptographicType.fromKey(key))
                .filter(cryptoOperation -> cryptoOperation.getKeyClass().isAssignableFrom(key.getClass()))
                .findAny()
                .orElseThrow(UnsupportedOperationException::new);


    }
}
