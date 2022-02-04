package com.somesec.crypto.constant;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;

public enum CryptoOperation {
    SYMMETRIC, ASYMMETRIC;



    public static CryptoOperation fromKey(Key key) {
        if (key == null) {
            throw new IllegalArgumentException(MessagesCode.ERROR_KEY_NOT_NULLABLE.getMessage());
        }
        if (key instanceof PrivateKey) {
            return CryptoOperation.ASYMMETRIC;
        } else if (key instanceof SecretKey) {
            return CryptoOperation.SYMMETRIC;
        } else {
            throw new IllegalArgumentException(MessagesCode.ERROR_KEY_TYPE_NOT_SUPPORTED.getMessage(key.getClass().getSimpleName()));
        }
    }
}
