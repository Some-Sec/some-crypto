package com.somesec.crypto.token;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

enum JWCryptographicAlgorithm {
    AES {
        @Override
        protected JWEEncrypter getEncrypter(final Key key) throws JOSEException {
            return new DirectEncrypter((SecretKey) key);
        }

        @Override
        protected JWEDecrypter getDecrypter(final Key key) throws JOSEException {
            return new DirectDecrypter((SecretKey) key);
        }

        @Override
        protected JWEHeader getEncryptionHeader() {
            return new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
        }

        @Override
        protected JWSHeader getSignatureHeader() {
            return new JWSHeader(JWSAlgorithm.HS256);
        }

        @Override
        protected JWSSigner getSigner(final Key key) throws JOSEException {
            return new MACSigner((SecretKey) key);
        }

        @Override
        protected JWSVerifier getVerifier(final Key key) throws JOSEException {
            return new MACVerifier((SecretKey) key);
        }
    }, RSA {
        @Override
        protected JWEEncrypter getEncrypter(final Key key) {
            return new RSAEncrypter((RSAPublicKey) key);
        }

        @Override
        protected JWEDecrypter getDecrypter(final Key key) {
            return new RSADecrypter((PrivateKey) key);
        }

        @Override
        protected JWEHeader getEncryptionHeader() {
            return new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
        }

        @Override
        protected JWSHeader getSignatureHeader() {
            return new JWSHeader(JWSAlgorithm.RS256);
        }

        @Override
        protected JWSSigner getSigner(final Key key) {
            return new RSASSASigner((PrivateKey) key);
        }

        @Override
        protected JWSVerifier getVerifier(final Key key) {
            return new RSASSAVerifier((RSAPublicKey) key);
        }
    }, ECDSA {
        @Override
        protected JWEEncrypter getEncrypter(final Key key) throws JOSEException {
            return new ECDHEncrypter((ECPublicKey) key);
        }

        @Override
        protected JWEDecrypter getDecrypter(final Key key) throws JOSEException {
            return new ECDHDecrypter((ECPrivateKey) key);
        }

        @Override
        protected JWEHeader getEncryptionHeader() {
            return new JWEHeader(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM);
        }

        @Override
        protected JWSHeader getSignatureHeader() {
            return new JWSHeader(JWSAlgorithm.ES256);
        }

        @Override
        protected JWSSigner getSigner(final Key key) throws JOSEException {
            return new ECDSASigner((ECPrivateKey) key);
        }

        @Override
        protected JWSVerifier getVerifier(final Key key) throws JOSEException {
            return new ECDSAVerifier((ECPublicKey) key);
        }
    };


    protected abstract JWEEncrypter getEncrypter(final Key key) throws JOSEException;

    protected abstract JWEDecrypter getDecrypter(final Key key) throws JOSEException;

    protected abstract JWEHeader getEncryptionHeader();

    protected abstract JWSHeader getSignatureHeader();

    protected abstract JWSSigner getSigner(final Key key) throws JOSEException;

    protected abstract JWSVerifier getVerifier(final Key key) throws JOSEException;
}
