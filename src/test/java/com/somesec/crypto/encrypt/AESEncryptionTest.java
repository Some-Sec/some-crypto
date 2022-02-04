package com.somesec.crypto.encrypt;

import com.somesec.crypto.config.ConfigurationResolverImpl;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.Security;
import java.util.Base64;
import java.util.Collections;

public class AESEncryptionTest {

    private static final String AES_KEY_256_B64 = "dSgVkXp2s5v8y/B?E(H+MbQeThWmZq3t";
    private static final String PLAIN_TEXT = "super test";

    private final EncryptionService service = new EncryptionServiceImpl(Collections.singletonList(new AESEncryption(new ConfigurationResolverImpl())));

    @Test
    public void aesSymmetricEncryptTest() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Key aesKey = new SecretKeySpec(AES_KEY_256_B64.getBytes(), "AES");
        byte[] encryptedBytes = service.encrypt(PLAIN_TEXT.getBytes(StandardCharsets.UTF_8), aesKey);
        Assert.assertNotNull(encryptedBytes);
        System.out.println(Base64.getEncoder().encodeToString(encryptedBytes));
    }
}
