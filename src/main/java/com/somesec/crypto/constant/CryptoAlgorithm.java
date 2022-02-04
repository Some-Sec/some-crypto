package com.somesec.crypto.constant;

import com.somesec.crypto.key.KeyGenParameters;

public interface CryptoAlgorithm {

    CryptographicType getCryptoOperation();

    KeyGenParameters getKeyGenParameters();

    String name();

}
