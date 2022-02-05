package com.somesec.crypto;

import com.somesec.crypto.constant.CryptographicType;

import java.security.Key;

public interface CryptographicOperation {

    CryptographicType getSupportedOperation();

    Class<? extends Key> getKeyClass();

    String getAlgorithmName();
}
