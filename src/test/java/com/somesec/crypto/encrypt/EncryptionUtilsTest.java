package com.somesec.crypto.encrypt;

import java.security.Key;
import java.security.Security;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

public class EncryptionUtilsTest {

    private static String AES_KEY_256_B64 = "dSgVkXp2s5v8y/B?E(H+MbQeThWmZq3t";
    private static String PLAIN_TEXT = "super test";

    @Test
    public void aesSymmetricEncryptTest() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Key aesKey = new SecretKeySpec(AES_KEY_256_B64.getBytes(), "AES");
        byte[] encryptedBytes = EncryptionUtils.aesSymmetricEncrypt(PLAIN_TEXT.getBytes("UTF-8"), aesKey);
        System.out.println(Base64.getEncoder().encodeToString(encryptedBytes));
    }
}
