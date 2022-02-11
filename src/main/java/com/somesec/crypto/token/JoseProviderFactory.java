package com.somesec.crypto.token;

import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;

import java.security.Key;

/**
 * Provider Factory to generate {@link com.nimbusds.jose.JOSEProvider} implementations based on {@link Key}
 */
public interface JoseProviderFactory {

    /**
     * This will instantiate a new JWE Encrypter, this encrypter is matching the algorithm corresponding to the Key passed in
     * @param key
     * @return concrete implementation of {@link JWEEncrypter} matching the algorithm of the {@link Key} passed in
     */
    JWEEncrypter getEncrypter(Key key);
    /**
     * This will instantiate a new JWE Decrypter, this decrypter is matching the algorithm corresponding to the Key passed in
     * @param key
     * @return concrete implementation of {@link JWEDecrypter} matching the algorithm of the {@link Key} passed in
     */
    JWEDecrypter getDecrypter(Key key);

    /**
     * This will instantiate a new JWS Signer, this signer is matching the algorithm corresponding to the Key passed in
     * @param key
     * @return concrete implementation of {@link JWSSigner} matching the algorithm of the {@link Key} passed in
     */
    JWSSigner getSigner(Key key);

    /**
     * This will instantiate a new JWS Verifier, this verifier is matching the algorithm corresponding to the Key passed in
     * @param key
     * @return concrete implementation of {@link JWSVerifier} matching the algorithm of the {@link Key} passed in
     */
    JWSVerifier getVerifier(Key key);

    /**
     * To successfully create a JWE Token, you will need a valid header. To assist this there are HeaderBuilders.
     * This function will return a header builder prefilled with the algorithm corresponding to the key type passed in.
     * @param key
     * @return prefilled JWEHeaderBuilder
     */
    JWEHeader.Builder getJWEHeaderBuilder(Key key);

    /**
     * To successfully create a JWS Token, you will need a valid header. To assist this there are HeaderBuilders.
     * This function will return a header builder prefilled with the algorithm corresponding to the key type passed in.
     * @param key
     * @return prefilled JWSHeaderBuilder
     */
    JWSHeader.Builder getJWSHeaderBuilder(Key key);


}
