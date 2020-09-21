package com.somesec.crypto.token;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.somesec.crypto.CryptoConstantsEnum;

public class TokenServiceDefaultImpl implements TokenService {

    @Override
    public String createJWE(String payload, byte[] publicKey) {
        return TokenUtils.createJWE((JWEAlgorithm) CryptoConstantsEnum.TOKEN_DEFAULT_ALGORITHM.getValue(),
            (EncryptionMethod) CryptoConstantsEnum.TOKEN_DEFAULT_ENCRYPTION_METHOD.getValue(), payload, publicKey);
    }

    @Override
    public String decryptJWE(String jwe, byte[] privateKey) {
        return TokenUtils.decryptJWE(jwe, privateKey);
    }
}
