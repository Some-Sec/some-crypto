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
     * @param payload to be encrypted
     * @param key to encrypt the payload
     * @param header the {@link com.nimbusds.jose.Header} specifying the algorithm
     * @return the encrypted payload in form of a {@link com.nimbusds.jose.JWEObject}
     */
    String createJWE(String payload, Key key, JWEHeader header);


    /**
     * This method uses json web cryptography to decrypt an existing JWEToken
     *
     * @param jwe the encrypted serialized JWE
     * @param key to encrypt the payload
     * @return the decrypted payload as a String
     */
    String decryptJWE(String jwe, Key key);

    /**
     * Creates and serializes a Signed JWT token also know as JWS
     * @param claims the set of claims to be signed and to be the content of the token
     * @param key private key to sign the claims
     * @param header the header containing the algorithm used for the JWS creation
     * @return a serialized and signed JWT commonly known as JWS
     */
    String createSignedJWT(JWTClaimsSet claims, Key key, JWSHeader header);

    /**
     * Verify JWS signature and therefore the token integrity. Will throw an exception if the integrity cant be verified
     * @param token the signed serialized JWS
     * @param key public key to verify the signature of the JWS
     * @return the untempered claim set
     */
    JWTClaimsSet verifyJWS(String token, Key key);


    /**
     * Fetches a new JWEHeader builder instance with the correct algorithm corresponding to the key passed in
     * @param key that is needed to get the information about the algorithm for the JWE header
     * @return Builder to create the correct JWEHeader
     */
    JWEHeader.Builder jweHeaderBuilderFromKey(Key key);

    /**
     * Fetches a new JWSHeader builder instance with the correct algorithm corresponding to the key passed in
     * @param key that is needed to get the information about the algorithm for the JWS header
     * @return Builder to create the correct JWSHeader
     */
    JWSHeader.Builder jwsHeaderBuilderFromKey(Key key);
}
