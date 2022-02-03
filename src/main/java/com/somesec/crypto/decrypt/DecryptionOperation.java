package com.somesec.crypto.decrypt;

import com.somesec.crypto.CryptoOperation;

import java.security.Key;

public interface DecryptionOperation {
    byte[] decrypt(byte[] cypheredBytes, Key key);

    CryptoOperation getSupportedOperation();

    Class<? extends Key> getKeyClass();
}