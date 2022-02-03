package com.somesec.crypto.constant;

import com.somesec.crypto.key.KeyGenParameters;

public interface CryptoAlgorithm {

    CryptoOperation getCryptoOperation();

    KeyGenParameters getKeyGenParameters();

    String name();

}
