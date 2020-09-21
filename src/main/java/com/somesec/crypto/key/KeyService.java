package com.somesec.crypto.key;

import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

/**
 * KeyService interface used in all other sec-channel components. Utility for key generation and parsing based on default parameters of the implementation.
 */
public interface KeyService {

    Key getAesKeyForPassphrase(char[] passphrase) throws Exception;

    KeyPair generateEcKeyPair();

    KeyPair generateRSAKeyPair();

    Key generateAesKey();

    PrivateKey deserializePrivateKey(String key) throws Exception;

    PublicKey deserializePublicKey(String key) throws Exception;

    String getKeyFingerprint(Key key) throws Exception;

    Key generateAesKeyFromHkdf(byte[] inputData) throws Exception;

    Key deserializeAESKey(String secret);
}
