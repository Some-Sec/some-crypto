package com.somesec.crypto.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEHeader.Builder;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.somesec.crypto.constant.MessagesCode;
import com.somesec.crypto.exception.CryptoOperationException;

import java.security.Key;
import java.text.ParseException;
import java.util.Objects;
import java.util.stream.Stream;

public class TokenServiceDefaultImpl implements TokenService {


    private final JoseProviderFactory joseProviderFactory;

    public TokenServiceDefaultImpl() {
        this.joseProviderFactory = new JoseProviderFactoryImpl();
    }

    public TokenServiceDefaultImpl(final JoseProviderFactory joseProviderFactory) {
        this.joseProviderFactory = joseProviderFactory;
    }

    @Override
    public String createJWE(final String payload, final Key key, final JWEHeader header) {
        if (Stream.of(payload, key, header).anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException("Payload, Key and JWE Header are mandatory");
        }
        try {
            final Payload jwePayload = new Payload(payload);
            final JWEObject jwe = new JWEObject(header, jwePayload);
            final JWEEncrypter encrypter = joseProviderFactory.getEncrypter(key);
            jwe.encrypt(encrypter);
            return jwe.serialize();
        } catch (JOSEException e) {
            throw new CryptoOperationException(MessagesCode.ERROR_JWE_CREATION, e);
        }
    }

    @Override
    public String decryptJWE(final String jwePayload, final Key key) {
        if (Stream.of(jwePayload, key).anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException("Payload and Key and are mandatory");
        }
        try {
            final JWEObject jwe = JWEObject.parse(jwePayload);
            final JWEDecrypter decrypter = joseProviderFactory.getDecrypter(key);
            jwe.decrypt(decrypter);
            return jwe.getPayload().toString();
        } catch (ParseException | JOSEException e) {
            throw new CryptoOperationException(MessagesCode.ERROR_JWE_DECRYPTION, e);
        }

    }

    @Override
    public String createSignedJWT(final JWTClaimsSet claims, final Key key, final JWSHeader header) {
        if (Stream.of(claims, key, header).anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException("Claims, Payload and Key and are mandatory");
        }
        try {
            final SignedJWT signedJWT = new SignedJWT(header, claims);
            signedJWT.sign(joseProviderFactory.getSigner(key));
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new CryptoOperationException(MessagesCode.ERROR_JWS_SIGNING);
        }

    }

    @Override
    public JWTClaimsSet verifyJWS(final String token, final Key key) {
        if (Stream.of(token, key).anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException("Claims, Payload and Key and are mandatory");
        }
        try {
            final SignedJWT signedJWT = SignedJWT.parse(token);
            final JWSVerifier verifier = joseProviderFactory.getVerifier(key);
            if (signedJWT.verify(verifier)) {
                return signedJWT.getJWTClaimsSet();
            } else {
                throw new CryptoOperationException(MessagesCode.ERROR_JWS_INTEGRITY_CHECK_FAILED);
            }
        } catch (ParseException | JOSEException e) {
            throw new CryptoOperationException(MessagesCode.ERROR_JWS_PARSING_FAILED);
        }
    }


    @Override
    public Builder jweHeaderBuilderFromKey(final Key key) {
        return joseProviderFactory.getJWEHeaderBuilder(key);
    }

    @Override
    public JWSHeader.Builder jwsHeaderBuilderFromKey(final Key key) {
        return joseProviderFactory.getJWSHeaderBuilder(key);
    }


}
