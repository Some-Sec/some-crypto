package com.somesec.crypto.token;

import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;

import java.security.Key;

/**
 * A Service dedicated to deal with Jason Web Token.
 */
public interface TokenService {
    /**
     * This method uses jason web cryptography to create an encrypted envelope of some payload
     *
     * @param payload
     * @param key
     * @return the encrypted payload in form of a {@link com.nimbusds.jose.JWEObject}
     */
    String createJWE(String payload, Key key, JWEHeader header);


    /**
     * This method uses jason web cryptography to decrypt an existing JWEToken
     *
     * @param jwe
     * @param key
     * @return the decrypted payload as a String
     */
    String decryptJWE(String jwe, Key key);

    /**
     * Creates and serializes a Signed JWT token also know as JWS
     * @param claims
     * @param key
     * @param header
     * @return a serialized and signed JWT commonly known as JWS
     */
    String createSignedJWT(JWTClaimsSet claims, Key key, JWSHeader header);

    /**
     * Verify JWS signature and therefore the token integrity. Will throw an exception if the integrity cant be verified
     * @param token
     * @param key
     * @return the untempered claim set
     */
    JWTClaimsSet verifyJWS(String token, Key key);


    /**
     * Fetches a new JWEHeader builder instance with the correct algorithm corresponding to the key passed in
     * @param key
     * @return Builder to create the correct JWEHeader
     */
    JWEHeader.Builder jweHeaderBuilderFromKey(Key key);

    /**
     * Fetches a new JWSHeader builder instance with the correct algorithm corresponding to the key passed in
     * @param key
     * @return Builder to create the correct JWSHeader
     */
    JWSHeader.Builder jwsHeaderBuilderFromKey(Key key);
}
