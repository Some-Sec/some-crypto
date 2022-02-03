package com.somesec.crypto.token;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.somesec.crypto.CryptoConstantsEnum;
import com.somesec.crypto.MessagesCode;
import com.somesec.crypto.exception.CryptoOperationException;

public class TokenUtils {

    public static String createJWE(JWEAlgorithm alg, EncryptionMethod enc, final String payload, final byte[] publicKey) {
        try {
            final JWEObject jwe = new JWEObject(
                new JWEHeader(alg, enc),
                new Payload(payload));
            jwe.encrypt(new RSAEncrypter(
                (RSAPublicKey) KeyFactory.getInstance((String) CryptoConstantsEnum.RSA.getValue()).generatePublic(new X509EncodedKeySpec(publicKey))));
            return jwe.serialize();
        } catch (Exception ex) {
            throw new CryptoOperationException(MessagesCode.ERROR_JWE_CREATION, ex);
        }
    }

    public static String decryptJWE(final String payload, final byte[] privKey) {
        try {
            final JWEObject jwe = JWEObject.parse(payload);
            jwe.decrypt(
                new RSADecrypter(KeyFactory.getInstance((String) CryptoConstantsEnum.RSA.getValue()).generatePrivate(new PKCS8EncodedKeySpec(privKey))));
            return jwe.getPayload().toString();
        } catch (Exception ex) {
            throw new CryptoOperationException(MessagesCode.ERROR_JWE_DECRYPTION, ex);

        }
    }
}
