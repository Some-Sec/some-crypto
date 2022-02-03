package com.somesec.crypto.constant;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;

public enum CryptoOperation {
    SYMMETRIC, ASYMMETRIC;


    private static final String KEY_TYPE_NOT_SUPPORTED = "KeyType [%s] not supported";

    public static CryptoOperation fromKey(Key key){
        if (key instanceof PrivateKey) {
            return CryptoOperation.ASYMMETRIC;
        } else if (key instanceof SecretKey) {
            return CryptoOperation.SYMMETRIC;
        } else {
            throw new IllegalArgumentException(String.format(KEY_TYPE_NOT_SUPPORTED, key.getClass().getSimpleName()));
        }
    }
}
