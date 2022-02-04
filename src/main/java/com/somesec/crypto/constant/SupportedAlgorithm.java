package com.somesec.crypto.constant;


import com.somesec.crypto.key.KeyGenAesParameters;
import com.somesec.crypto.key.KeyGenEcParameters;
import com.somesec.crypto.key.KeyGenParameters;
import com.somesec.crypto.key.KeyGenRsaParameters;

public enum SupportedAlgorithm implements CryptoAlgorithm {

    AES {
        @Override
        public CryptographicType getCryptoOperation() {
            return CryptographicType.SYMMETRIC;
        }

        @Override
        public KeyGenParameters getKeyGenParameters() {
            return new KeyGenAesParameters(CryptoConstants.KEY_DEFAULT_AES_KEY_SIZE.getValue());
        }
    }, RSA {
        @Override
        public CryptographicType getCryptoOperation() {
            return CryptographicType.ASYMMETRIC;
        }

        @Override
        public KeyGenParameters getKeyGenParameters() {
            return new KeyGenRsaParameters(CryptoConstants.KEY_DEFAULT_RSA_SIZE.getValue());
        }
    }, ECDSA {
        @Override
        public CryptographicType getCryptoOperation() {
            return CryptographicType.ASYMMETRIC;
        }

        @Override
        public KeyGenParameters getKeyGenParameters() {
            return new KeyGenEcParameters(CryptoConstants.KEY_DEFAULT_ECDSA_CURVE_NAME.getValue());
        }
    };


}
