package com.somesec.crypto.key;

import java.security.Key;
import java.security.KeyPair;
import java.security.Security;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

public class KeyUtilsTest {

    @Test
    public void serializeAndDeserializeRsaTest() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        final KeyPair keyPair = KeyUtils.generateKeyPair("RSA", new KeyGenRsaParameters(1024));
        final Key publicKey = KeyUtils.deserializeAsymmetricPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        final Key privateKey = KeyUtils.deserializeAsymmetricPrivateKey(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
    }

    @Test
    public void serializeAndDeserializeEcdsaTest() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        final KeyPair keyPair = KeyUtils.generateKeyPair("ECDSA", new KeyGenEcParameters("secp256r1"));
        final Key publicKey = KeyUtils.deserializeAsymmetricPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        final Key privateKey = KeyUtils.deserializeAsymmetricPrivateKey(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
    }
}
