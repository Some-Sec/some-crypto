package com.somesec.crypto.encrypt;

import com.somesec.crypto.constant.CryptographicType;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.List;

/**
 * {@see EncryptionService}
 */
public class EncryptionServiceImpl implements EncryptionService {

    private static final Base64.Encoder B_64_ENCODER = Base64.getEncoder();

    private final List<EncryptionOperation> cryptoOperations;

    public EncryptionServiceImpl(List<EncryptionOperation> cryptoOperations) {
        this.cryptoOperations = cryptoOperations;
    }


    @Override
    public String encrypt(String plaintext, Key key) {
        return B_64_ENCODER.encodeToString(this.encrypt(plaintext.getBytes(StandardCharsets.UTF_8), key));
    }

    @Override
    public byte[] encrypt(byte[] plaintextBytes, Key key) {
        final EncryptionOperation encryptionOperation = findSupportedOperation(key);
        return encryptionOperation.encrypt(plaintextBytes, key);

    }

    @Override
    public void encrypt(InputStream plainText, OutputStream cipherText, Key key) {
        final EncryptionOperation encryptionOperation = findSupportedOperation(key);
        encryptionOperation.encrypt(plainText,cipherText,key);
    }

    // todo unit test
    protected EncryptionOperation findSupportedOperation(Key key) {

        return cryptoOperations
                .stream()
                .filter(cryptoOperation -> cryptoOperation.getSupportedOperation() == CryptographicType.fromKey(key))
                .filter(cryptoOperation -> cryptoOperation.getKeyClass().isAssignableFrom(key.getClass()))
                .findAny()
                .orElseThrow(UnsupportedOperationException::new);


    }
}
