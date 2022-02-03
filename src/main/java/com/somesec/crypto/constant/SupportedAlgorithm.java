package com.somesec.crypto.constant;


import com.somesec.crypto.key.KeyGenAesParameters;
import com.somesec.crypto.key.KeyGenEcParameters;
import com.somesec.crypto.key.KeyGenParameters;
import com.somesec.crypto.key.KeyGenRsaParameters;

public enum SupportedAlgorithm implements CryptoAlgorithm {

    AES {
        @Override
        public CryptoOperation getCryptoOperation() {
            return CryptoOperation.SYMMETRIC;
        }

        @Override
        public KeyGenParameters getKeyGenParameters() {
            return new KeyGenAesParameters(CryptoConstantsEnum.KEY_DEFAULT_AES_KEY_SIZE.getValue());
        }
    }, RSA {
        @Override
        public CryptoOperation getCryptoOperation() {
            return CryptoOperation.ASYMMETRIC;
        }

        @Override
        public KeyGenParameters getKeyGenParameters() {
            return new KeyGenRsaParameters(CryptoConstantsEnum.KEY_DEFAULT_RSA_SIZE.getValue());
        }
    }, ECDSA {
        @Override
        public CryptoOperation getCryptoOperation() {
            return CryptoOperation.ASYMMETRIC;
        }

        @Override
        public KeyGenParameters getKeyGenParameters() {
            return new KeyGenEcParameters(CryptoConstantsEnum.KEY_DEFAULT_ECDSA_CURVE_NAME.getValue());
        }
    };


}
