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

    String createSignedJWT(JWTClaimsSet claims, Key key, JWSHeader header);

    JWEHeader.Builder jweHeaderBuilderFromKey(Key key);

    JWSHeader.Builder jwsHeaderBuilderFromKey(Key key);
}
