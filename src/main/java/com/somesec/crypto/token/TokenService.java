package com.somesec.crypto.token;

/**
 * A Service dedicated to deal with Jason Web Token.
 */
public interface TokenService {
    /**
     * This method uses jason web cryptography to create an encrypted envelope of some payload
     * @param payload
     * @param publicKey
     * @return the encrypted payload in form of a {@link com.nimbusds.jose.JWEObject}
     * @throws Exception
     */
    String createJWE(String payload, byte[] publicKey) throws Exception;


    /**
     * This method uses jason web cryptography to decrypt an existing JWEToken
     * @param jwe
     * @param privateKey
     * @return the decrypted payload as a String
     * @throws Exception
     */
    String decryptJWE(String jwe, byte[] privateKey) throws Exception;
}
