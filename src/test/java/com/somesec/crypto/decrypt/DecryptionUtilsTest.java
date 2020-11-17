package com.somesec.crypto.decrypt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.Security;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

public class DecryptionUtilsTest {

    private static String AES_KEY_256_B64 = "dSgVkXp2s5v8y/B?E(H+MbQeThWmZq3t";
    private static String PLAIN_TEXT = "super test";
    private static String ENCRYPTED_TEXT_B64 = "fWXjhoK0d0tHprnG2mAASE4bI4x7wAXb3mYWwU5jv/NYHgbX6OU=";

    private static Base64.Decoder b64Decoder = Base64.getDecoder();

    @Test
    public void aesSymmetricDecryptTest()
    {
        Security.addProvider(new BouncyCastleProvider());
        Key aesKey = new SecretKeySpec(AES_KEY_256_B64.getBytes(), "AES");
        byte[] decryptedBytes = DecryptionUtils.aesSymmetricDecrypt(b64Decoder.decode(ENCRYPTED_TEXT_B64), aesKey);
        Assert.assertTrue(new String(decryptedBytes, StandardCharsets.UTF_8).equals(PLAIN_TEXT));
    }
}
