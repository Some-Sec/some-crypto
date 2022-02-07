package com.somesec.crypto.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEHeader.Builder;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.somesec.crypto.constant.MessagesCode;
import com.somesec.crypto.exception.CryptoOperationException;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.stream.Stream;

final class JoseProviderFactoryImpl implements JoseProviderFactory {


    @Override
    public JWEEncrypter getEncrypter(final Key key) {
        doKeyNullCheck(key);
        if (key instanceof PrivateKey) {
            throw new CryptoOperationException(MessagesCode.ERROR_KEY_TYPE_NOT_SUPPORTED, PrivateKey.class.getSimpleName());
        }
        final JWCryptographicAlgorithm algo = findAlgorithmByKey(key);
        try {
            return algo.getEncrypter(key);
        } catch (JOSEException e) {
            throw new CryptoOperationException(MessagesCode.ERROR_JOSE_PROVIDER_CREATION);
        }
    }

    @Override
    public JWEDecrypter getDecrypter(final Key key) {
        doKeyNullCheck(key);
        if (key instanceof PublicKey) {
            throw new CryptoOperationException(MessagesCode.ERROR_KEY_TYPE_NOT_SUPPORTED, PublicKey.class.getSimpleName());
        }
        final JWCryptographicAlgorithm algo = findAlgorithmByKey(key);
        try {
            return algo.getDecrypter(key);
        } catch (JOSEException e) {
            throw new CryptoOperationException(MessagesCode.ERROR_JOSE_PROVIDER_CREATION);
        }

    }

    @Override
    public JWSSigner getSigner(final Key key) {
        doKeyNullCheck(key);
        if (key instanceof PublicKey) {
            throw new CryptoOperationException(MessagesCode.ERROR_KEY_TYPE_NOT_SUPPORTED, PublicKey.class.getSimpleName());
        }
        final JWCryptographicAlgorithm algo = findAlgorithmByKey(key);
        try {
            return algo.getSigner(key);
        } catch (JOSEException e) {
            throw new CryptoOperationException(MessagesCode.ERROR_JOSE_PROVIDER_CREATION);
        }
    }

    @Override
    public JWSVerifier getVerifier(final Key key) {
        doKeyNullCheck(key);
        if (key instanceof PrivateKey) {
            throw new CryptoOperationException(MessagesCode.ERROR_KEY_TYPE_NOT_SUPPORTED, PrivateKey.class.getSimpleName());
        }
        final JWCryptographicAlgorithm algo = findAlgorithmByKey(key);
        try {
            return algo.getVerifier(key);
        } catch (JOSEException e) {
            throw new CryptoOperationException(MessagesCode.ERROR_JOSE_PROVIDER_CREATION);
        }
    }

    @Override
    public Builder getJWEHeaderBuilder(final Key key) {
        doKeyNullCheck(key);
        final JWCryptographicAlgorithm algo = findAlgorithmByKey(key);
        return new JWEHeader.Builder(algo.getEncryptionHeader());
    }

    @Override
    public JWSHeader.Builder getJWSHeaderBuilder(final Key key) {
        doKeyNullCheck(key);
        final JWCryptographicAlgorithm algo = findAlgorithmByKey(key);
        return new JWSHeader.Builder(algo.getSignatureHeader());
    }

    private void doKeyNullCheck(final Key key) {
        if (key == null) {
            throw new IllegalArgumentException(MessagesCode.ERROR_KEY_NOT_NULLABLE.getMessage());
        }
    }

    private JWCryptographicAlgorithm findAlgorithmByKey(final Key key) {
        final String algo = key.getAlgorithm();
        return Stream.of(JWCryptographicAlgorithm.values())
                .filter(algorithm -> algorithm.name().equalsIgnoreCase(algo))
                .findAny()
                .orElseThrow(() -> new CryptoOperationException(MessagesCode.ERROR_ALGO_NOT_SUPPORTED, algo));
    }


}
