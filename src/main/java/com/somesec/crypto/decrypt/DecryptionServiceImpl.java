package com.somesec.crypto.decrypt;

import com.somesec.crypto.CryptoOperation;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.util.List;

public class DecryptionServiceImpl implements DecryptionService {

    private static final String KEY_TYPE_NOT_SUPPORTED = "KeyType [{}] not supported";
    private List<DecryptionOperation> cryptoOperations;


    @Override
    public String decrypt(String cypheredText, Key key) {
        return new String(this.decrypt(cypheredText.getBytes(StandardCharsets.UTF_8), key), StandardCharsets.UTF_8);
    }

    @Override
    public byte[] decrypt(byte[] cypheredBytes, Key key) {
        if (key instanceof PrivateKey) {
            // todo, implement async decryption
            throw new IllegalStateException("Method not implemented");
        } else if (key instanceof SecretKey) {
            final DecryptionOperation decryptionOperation = findSupportedOperation(CryptoOperation.SYMMETRIC, key.getClass());
            return decryptionOperation.decrypt(cypheredBytes,key);
//            return DecryptionUtils.aesSymmetricDecrypt(cypheredBytes, key);
        } else {
            throw new IllegalArgumentException(String.format(KEY_TYPE_NOT_SUPPORTED, key.getClass()));
        }

    }


    private DecryptionOperation findSupportedOperation(CryptoOperation cryptoOperation, Class<? extends Key> keyClass) {
        return cryptoOperations.stream()
                .filter(decryptionOperation -> decryptionOperation.getSupportedOperation() == cryptoOperation)
                .filter(decryptionOperation -> keyClass.isAssignableFrom(decryptionOperation.getKeyClass()))
                .findAny()
                .orElseThrow(UnsupportedOperationException::new);

    }
}
