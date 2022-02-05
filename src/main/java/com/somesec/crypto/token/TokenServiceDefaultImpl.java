package com.somesec.crypto.token;

import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.somesec.crypto.config.ConfigurationResolver;
import com.somesec.crypto.config.DefaultConfig;
import com.somesec.crypto.key.KeyOperation;

import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class TokenServiceDefaultImpl implements TokenService {

    private final ConfigurationResolver resolver;

    private final KeyOperation keyOperation;

    public TokenServiceDefaultImpl(final ConfigurationResolver resolver, final KeyOperation keyOperation) {
        this.resolver = resolver;
        this.keyOperation = keyOperation;
    }

    @Override
    public String createJWE(String payload, byte[] publicKey) throws Exception {
        final JWEObject jwe = new JWEObject(
                new JWEHeader(resolver.getConfig(DefaultConfig.TOKEN_ALGORITHM), resolver.getConfig(DefaultConfig.TOKEN_ENCRYPTION_METHOD)),
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
