package com.somesec.crypto.constant;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;

public enum CryptographicType {
    SYMMETRIC, ASYMMETRIC;



    public static CryptographicType fromKey(Key key) {
        if (key == null) {
            throw new IllegalArgumentException(MessagesCode.ERROR_KEY_NOT_NULLABLE.getMessage());
        }
        if (key instanceof PrivateKey) {
            return CryptographicType.ASYMMETRIC;
        } else if (key instanceof SecretKey) {
            return CryptographicType.SYMMETRIC;
        } else {
            throw new IllegalArgumentException(MessagesCode.ERROR_KEY_TYPE_NOT_SUPPORTED.getMessage(key.getClass().getSimpleName()));
        }
    }
}
