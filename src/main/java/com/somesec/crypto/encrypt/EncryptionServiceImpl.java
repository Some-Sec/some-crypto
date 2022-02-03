package com.somesec.crypto.encrypt;

import com.somesec.crypto.constant.CryptoOperation;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.List;

public class EncryptionServiceImpl implements EncryptionService {

    private final static Base64.Encoder B_64_ENCODER = Base64.getEncoder();

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

    // todo unit test
    protected EncryptionOperation findSupportedOperation(Key key) {

        return cryptoOperations
                .stream()
                .filter(decryptionOperation -> decryptionOperation.getSupportedOperation() == CryptoOperation.fromKey(key))
                .filter(decryptionOperation -> decryptionOperation.getKeyClass().isAssignableFrom(key.getClass()))
                .findAny()
                .orElseThrow(UnsupportedOperationException::new);


    }
}
