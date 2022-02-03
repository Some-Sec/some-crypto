package com.somesec.crypto.key;

import com.somesec.crypto.constant.CryptoAlgorithm;

import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

/**
 * KeyService interface used in all other sec-channel components. Utility for key generation and parsing based on default parameters of the implementation.
 */
public interface KeyOperation {

    Key deriveSecretKey(char[] passphrase, CryptoAlgorithm algorithm) throws Exception;

    KeyPair generateKeyPair(CryptoAlgorithm algorithm);

    Key generateSecretKey();

    PrivateKey deserializePrivateKey(String key) throws Exception;

    PublicKey deserializePublicKey(String key) throws Exception;

    String getKeyFingerprint(Key key) throws Exception;

    Key deserializeSecretKey(String secret);
}
