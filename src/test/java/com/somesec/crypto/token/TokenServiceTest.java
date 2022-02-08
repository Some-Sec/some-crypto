package com.somesec.crypto.token;

import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.somesec.crypto.config.ConfigurationResolverImpl;
import com.somesec.crypto.constant.MessagesCode;
import com.somesec.crypto.constant.SupportedAlgorithm;
import com.somesec.crypto.exception.CryptoOperationException;
import com.somesec.crypto.key.DefaultKeyOperationImpl;
import com.somesec.crypto.key.KeyOperation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TokenServiceTest {

    public static final String PAYLOAD = "Hello world";
    private TokenService tokenService = new TokenServiceDefaultImpl();
    private KeyOperation keyOperation = new DefaultKeyOperationImpl(new ConfigurationResolverImpl());

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void testAESJWE() {
        final Key key = keyOperation.generateSecretKey();
        final JWEHeader jweHeader = tokenService.jweHeaderBuilderFromKey(key).build();
        final String jwe = tokenService.createJWE(PAYLOAD, key, jweHeader);
        assertNotNull(jwe);
        assertThrows(CryptoOperationException.class, () -> tokenService.decryptJWE(jwe, keyOperation.generateSecretKey()), MessagesCode.ERROR_JWE_DECRYPTION.getMessage());
        final String decryptJWE = tokenService.decryptJWE(jwe, key);
        assertEquals(PAYLOAD, decryptJWE);

    }

    @Test
    void testRSAJWE() {
        final KeyPair senderPair = keyOperation.generateKeyPair(SupportedAlgorithm.RSA);
        final KeyPair receiverPair = keyOperation.generateKeyPair(SupportedAlgorithm.RSA);
        final KeyPair ecKeyPair = keyOperation.generateKeyPair(SupportedAlgorithm.ECDSA);
        final JWEHeader jweHeader = tokenService.jweHeaderBuilderFromKey(receiverPair.getPublic()).build();
        final String jwe = tokenService.createJWE(PAYLOAD, receiverPair.getPublic(), jweHeader);
        assertThrows(CryptoOperationException.class, () -> tokenService.createJWE(PAYLOAD, ecKeyPair.getPublic(), jweHeader));
        assertNotNull(jwe);
        assertThrows(CryptoOperationException.class, () -> tokenService.decryptJWE(jwe, receiverPair.getPublic()), MessagesCode.ERROR_KEY_TYPE_NOT_SUPPORTED.getMessage(PublicKey.class.getSimpleName()));
        assertThrows(CryptoOperationException.class, () -> tokenService.decryptJWE(jwe, senderPair.getPrivate()), MessagesCode.ERROR_JWE_DECRYPTION.getMessage());
        final String s = tokenService.decryptJWE(jwe, receiverPair.getPrivate());
        assertEquals(PAYLOAD, s);

    }

    @Test
    void testECJWE() {
        final KeyPair senderPair = keyOperation.generateKeyPair(SupportedAlgorithm.ECDSA);
        final KeyPair receiverPair = keyOperation.generateKeyPair(SupportedAlgorithm.ECDSA);
        final KeyPair rsaKeyPair = keyOperation.generateKeyPair(SupportedAlgorithm.RSA);
        final JWEHeader jweHeader = tokenService.jweHeaderBuilderFromKey(receiverPair.getPublic()).build();
        final String jwe = tokenService.createJWE(PAYLOAD, receiverPair.getPublic(), jweHeader);
        assertThrows(CryptoOperationException.class, () -> tokenService.createJWE(PAYLOAD, rsaKeyPair.getPublic(), jweHeader));
        assertNotNull(jwe);
        assertThrows(CryptoOperationException.class, () -> tokenService.decryptJWE(jwe, receiverPair.getPublic()), MessagesCode.ERROR_KEY_TYPE_NOT_SUPPORTED.getMessage(PublicKey.class.getSimpleName()));
        assertThrows(CryptoOperationException.class, () -> tokenService.decryptJWE(jwe, senderPair.getPrivate()), MessagesCode.ERROR_JWE_DECRYPTION.getMessage());
        final String s = tokenService.decryptJWE(jwe, receiverPair.getPrivate());
        assertEquals(PAYLOAD, s);

    }

    @Test
    void testAESJWS() throws ParseException {
        final Key key = keyOperation.generateSecretKey();
        final Key wrongKey = keyOperation.generateSecretKey();
        final JWSHeader jwsHeader = tokenService.jwsHeaderBuilderFromKey(key).build();
        final Map<String, Object> claims = new HashMap<>();
        claims.put("aud", PAYLOAD);
        final JWTClaimsSet claimsSet = JWTClaimsSet.parse(claims);
        final String jws = tokenService.createSignedJWT(claimsSet, key, jwsHeader);
        final JWTClaimsSet jwtClaimsSet = tokenService.verifyJWS(jws, key);
        assertThrows(CryptoOperationException.class, () -> tokenService.verifyJWS(jws, wrongKey), MessagesCode.ERROR_JWS_INTEGRITY_CHECK_FAILED.getMessage());
        assertEquals(PAYLOAD, jwtClaimsSet.getAudience().get(0));

    }

    @Test
    void testRSAJWS() throws ParseException {
        final KeyPair keyPair = keyOperation.generateKeyPair(SupportedAlgorithm.RSA);
        final KeyPair wrongKeyPair = keyOperation.generateKeyPair(SupportedAlgorithm.RSA);
        final JWSHeader jwsHeader = tokenService.jwsHeaderBuilderFromKey(keyPair.getPrivate()).build();
        final Map<String, Object> claims = new HashMap<>();
        claims.put("aud", PAYLOAD);
        final JWTClaimsSet claimsSet = JWTClaimsSet.parse(claims);
        final String jws = tokenService.createSignedJWT(claimsSet, keyPair.getPrivate(), jwsHeader);
        final JWTClaimsSet jwtClaimsSet = tokenService.verifyJWS(jws, keyPair.getPublic());
        assertThrows(CryptoOperationException.class, () -> tokenService.verifyJWS(jws, wrongKeyPair.getPublic()), MessagesCode.ERROR_JWS_INTEGRITY_CHECK_FAILED.getMessage());
        assertEquals(PAYLOAD, jwtClaimsSet.getAudience().get(0));

    }

    @Test
    void testECJWS() throws ParseException {
        final KeyPair keyPair = keyOperation.generateKeyPair(SupportedAlgorithm.ECDSA);
        final KeyPair wrongKeyPair = keyOperation.generateKeyPair(SupportedAlgorithm.RSA);
        final JWSHeader jwsHeader = tokenService.jwsHeaderBuilderFromKey(keyPair.getPrivate()).build();
        final Map<String, Object> claims = new HashMap<>();
        claims.put("aud", PAYLOAD);
        final JWTClaimsSet claimsSet = JWTClaimsSet.parse(claims);
        final String jws = tokenService.createSignedJWT(claimsSet, keyPair.getPrivate(), jwsHeader);
        final JWTClaimsSet jwtClaimsSet = tokenService.verifyJWS(jws, keyPair.getPublic());
        assertThrows(CryptoOperationException.class, () -> tokenService.verifyJWS(jws, wrongKeyPair.getPublic()), MessagesCode.ERROR_JWS_INTEGRITY_CHECK_FAILED.getMessage());
        assertEquals(PAYLOAD, jwtClaimsSet.getAudience().get(0));

    }
}