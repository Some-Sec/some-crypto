package com.somesec.crypto.constant;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;

public enum CryptographicType {
    /**
     * Represents Symmetric Cryptography such as AES
     */
    SYMMETRIC,
    /**
     * Represents Asymmetric Cryptography such as RSA
     */
    ASYMMETRIC;


/**
 * Construct a {@link CryptographicType} from a {@link Key}; This falls back into SYMMETRIC or ASYMMETRIC, depending on the Key type.
 **/
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
