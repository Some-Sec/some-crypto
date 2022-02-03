package com.somesec.crypto.key;

import com.somesec.crypto.constant.CryptoAlgorithm;

import java.security.*;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;

/**
 * KeyService interface used in all other sec-channel components. Utility for key generation and parsing based on default parameters of the implementation.
 */
public interface KeyOperation {

    Key deriveSecretKey(char[] passphrase, CryptoAlgorithm algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException;

    KeyPair generateKeyPair(CryptoAlgorithm algorithm) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException;

    Key generateSecretKey() throws NoSuchAlgorithmException, InvalidKeySpecException;

    PrivateKey deserializePrivateKey(String key) throws Exception;

    PublicKey deserializePublicKey(String key) throws Exception;

    String getKeyFingerprint(Key key) throws Exception;

    Key deserializeSecretKey(String secret);
}
