package com.somesec.crypto.token;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.somesec.crypto.constant.CryptoConstantsEnum;
import com.somesec.crypto.constant.MessagesCode;
import com.somesec.crypto.exception.CryptoOperationException;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class TokenUtils {

    public static String createJWE(JWEAlgorithm alg, EncryptionMethod enc, final String payload, final byte[] publicKey) {
        try {
            final JWEObject jwe = new JWEObject(
                    new JWEHeader(alg, enc),
                    new Payload(payload));
            jwe.encrypt(new RSAEncrypter(
                    (RSAPublicKey) KeyFactory.getInstance(CryptoConstantsEnum.RSA.getValue()).generatePublic(new X509EncodedKeySpec(publicKey))));
            return jwe.serialize();
        } catch (Exception ex) {
            throw new CryptoOperationException(MessagesCode.ERROR_JWE_CREATION, ex);
        }
    }

    public static String decryptJWE(final String payload, final byte[] privKey) {
        try {
            final JWEObject jwe = JWEObject.parse(payload);
            jwe.decrypt(
                    new RSADecrypter(KeyFactory.getInstance(CryptoConstantsEnum.RSA.getValue()).generatePrivate(new PKCS8EncodedKeySpec(privKey))));
            return jwe.getPayload().toString();
        } catch (Exception ex) {
            throw new CryptoOperationException(MessagesCode.ERROR_JWE_DECRYPTION, ex);

        }
    }
}
