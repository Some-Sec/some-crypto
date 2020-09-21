package com.somesec.crypto.encrypt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

public class EncryptionServiceDefaultImpl implements EncryptionService {

    private static Base64.Encoder b64encoder = Base64.getEncoder();

    @Override
    public String symEncryptDefault(String plaintext, Key key) {
        return b64encoder.encodeToString(EncryptionUtils.aesSymmetricEncrypt(plaintext.getBytes(StandardCharsets.UTF_8), key));
    }

    @Override
    public byte[] symEncryptDefault(byte[] plaintextBytes, Key key) {
        return EncryptionUtils.aesSymmetricEncrypt(plaintextBytes, key);
    }
}
