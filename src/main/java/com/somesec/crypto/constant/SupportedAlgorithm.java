package com.somesec.crypto.constant;


public enum SupportedAlgorithm implements CryptoAlgorithm {

    AES {
        @Override
        public CryptographicType getCryptoOperation() {
            return CryptographicType.SYMMETRIC;
        }

    }, RSA {
        @Override
        public CryptographicType getCryptoOperation() {
            return CryptographicType.ASYMMETRIC;
        }

    }, ECDSA {
        @Override
        public CryptographicType getCryptoOperation() {
            return CryptographicType.ASYMMETRIC;
        }

    };


}
