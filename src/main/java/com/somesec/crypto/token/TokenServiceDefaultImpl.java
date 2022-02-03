package com.somesec.crypto.token;

import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.somesec.crypto.constant.CryptoConstantsEnum;
import com.somesec.crypto.key.KeyOperation;

import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class TokenServiceDefaultImpl implements TokenService {


    private final KeyOperation keyOperation;

    public TokenServiceDefaultImpl(KeyOperation keyOperation) {
        this.keyOperation = keyOperation;
    }

    @Override
    public String createJWE(String payload, byte[] publicKey) throws Exception {
        final JWEObject jwe = new JWEObject(
                new JWEHeader(CryptoConstantsEnum.TOKEN_DEFAULT_ALGORITHM.getValue(), CryptoConstantsEnum.TOKEN_DEFAULT_ENCRYPTION_METHOD.getValue()),
                new Payload(payload));
        jwe.encrypt(new RSAEncrypter(
                (RSAPublicKey) keyOperation.deserializePublicKey(Base64.getEncoder().encodeToString(publicKey))));
        return jwe.serialize();

    }

    @Override
    public String decryptJWE(String payload, byte[] privateKey) throws Exception {
        final JWEObject jwe = JWEObject.parse(payload);
        jwe.decrypt(
                new RSADecrypter(keyOperation.deserializePrivateKey(Base64.getEncoder().encodeToString(privateKey))));
        return jwe.getPayload().toString();


    }


}
