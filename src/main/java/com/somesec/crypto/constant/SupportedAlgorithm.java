package com.somesec.crypto.constant;


public enum SupportedAlgorithm implements CryptoAlgorithm {

    AES {
        @Override
        public CryptographicType getCryptographicType() {
            return CryptographicType.SYMMETRIC;
        }

    }, RSA {
        @Override
        public CryptographicType getCryptographicType() {
            return CryptographicType.ASYMMETRIC;
        }

    }, ECDSA {
        @Override
        public CryptographicType getCryptographicType() {
            return CryptographicType.ASYMMETRIC;
        }

    };


}
