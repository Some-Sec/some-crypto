package com.somesec.crypto.decrypt;

import com.somesec.crypto.constant.CryptoOperation;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.List;

public class DecryptionServiceImpl implements DecryptionService {

    private final List<DecryptionOperation> cryptoOperations;

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

    // todo unit test
    protected DecryptionOperation findSupportedOperation(Key key) {

        return cryptoOperations
                .stream()
                .filter(decryptionOperation -> decryptionOperation.getSupportedOperation() == CryptoOperation.fromKey(key))
                .filter(decryptionOperation -> decryptionOperation.getKeyClass().isAssignableFrom(key.getClass()))
                .findAny()
                .orElseThrow(UnsupportedOperationException::new);


    }
}
