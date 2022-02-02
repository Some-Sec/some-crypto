package com.somesec.crypto.encrypt;

import com.somesec.crypto.CryptoOperation;

import java.security.Key;

public interface EncryptionOperation {

    byte[] encrypt(byte[] payload, Key key);

    CryptoOperation getSupportedOperation();

    Class<? extends Key> getKeyClass();

}
