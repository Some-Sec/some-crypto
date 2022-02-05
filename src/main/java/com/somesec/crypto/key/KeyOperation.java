package com.somesec.crypto.key;

import com.somesec.crypto.constant.CryptoAlgorithm;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * KeyService interface used in all other some-sec components. Utility for key generation and parsing based on default parameters of the implementation.
 */
public interface KeyOperation {
    /**
     * Key derivation based on PBKF2 as the name suggest this will generate a {@link javax.crypto.SecretKey} based of some passphrase
     *
     * @param passphrase
     * @param algorithm
     * @return new SecretKey based on passphrase
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    Key deriveSecretKey(char[] passphrase, CryptoAlgorithm algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException;

    /**
     * This will generate a {@link KeyPair} based on the passed in algorithm, RSA or ECDSA
     *
     * @param algorithm
     * @return freshly generated KeyPair for asymmetric cryptography
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    KeyPair generateKeyPair(CryptoAlgorithm algorithm) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException;

    /**
     * This method generates a new {@link javax.crypto.SecretKey}, it does this by generating a strong random value that will be passed into the deriveSecretKey function to generate higher amounts of entropy
     *
     * @return SecretKey based on a Strong random
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    Key generateSecretKey() throws NoSuchAlgorithmException, InvalidKeySpecException;

    /**
     * Deserializes a {@link PrivateKey} that is passed in in double encoded form like this Base64(Pem(PrivateKey))
     *
     * @param key
     * @return a private key object representing the key passed in
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    PrivateKey deserializePrivateKey(String key) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException;

    /**
     * Deserializes a {@link PublicKey} that is passed in in double encoded form like this Base64(Pem(PublicKey))
     *
     * @param key
     * @return a public key object representing the key passed in
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    PublicKey deserializePublicKey(String key) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException;

    /**
     * Creates the fingerprint of a key, in this implementation the hashing algorithm is at least Sha256
     *
     * @param key
     * @return Hashed representation of Key
     */
    String getKeyFingerprint(Key key);

    /**
     * This function deserializes a SecretKey that will be passed in Base64 encoded
     *
     * @param secret the base 64 encoded {@link javax.crypto.SecretKey}
     * @return the Key object
     */
    Key deserializeSecretKey(String secret);
}
