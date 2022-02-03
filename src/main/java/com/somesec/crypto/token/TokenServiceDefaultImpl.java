package com.somesec.crypto.token;

import com.somesec.crypto.constant.CryptoConstantsEnum;

public class TokenServiceDefaultImpl implements TokenService {

    @Override
    public String createJWE(String payload, byte[] publicKey) {
        return TokenUtils.createJWE(CryptoConstantsEnum.TOKEN_DEFAULT_ALGORITHM.getValue(),
                CryptoConstantsEnum.TOKEN_DEFAULT_ENCRYPTION_METHOD.getValue(), payload, publicKey);
    }

    @Override
    public String decryptJWE(String jwe, byte[] privateKey) {
        return TokenUtils.decryptJWE(jwe, privateKey);
    }
}
