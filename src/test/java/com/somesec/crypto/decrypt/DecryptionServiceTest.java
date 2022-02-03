package com.somesec.crypto.decrypt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.Security;
import java.util.Base64;
import java.util.Collections;

public class DecryptionServiceTest {

    private static final String AES_KEY_256_B64 = "dSgVkXp2s5v8y/B?E(H+MbQeThWmZq3t";
    private static final String PLAIN_TEXT = "super test";
    private static final String ENCRYPTED_TEXT_B64 = "fWXjhoK0d0tHprnG2mAASE4bI4x7wAXb3mYWwU5jv/NYHgbX6OU=";

    private static final Base64.Decoder b64Decoder = Base64.getDecoder();
    private final DecryptionService service = new DecryptionServiceImpl(Collections.singletonList(new AESDecryption()));


    @Test
    public void aesDecryptionTest() {
        Security.addProvider(new BouncyCastleProvider());
        Key aesKey = new SecretKeySpec(AES_KEY_256_B64.getBytes(), "AES");
        byte[] decryptedBytes = service.decrypt(b64Decoder.decode(ENCRYPTED_TEXT_B64), aesKey);
        Assert.assertEquals(PLAIN_TEXT, new String(decryptedBytes, StandardCharsets.UTF_8), PLAIN_TEXT);
    }
}
