package com.somesec.crypto.decrypt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

public class DecryptionServiceDefaultImpl implements DecryptionService {

    private static Base64.Decoder b64decoder = Base64.getDecoder();

    @Override
    public String symDecryptDefault(String cypheredText, Key key) {
        return new String(DecryptionUtils.aesSymmetricDecrypt(b64decoder.decode(cypheredText.getBytes(StandardCharsets.UTF_8)), key), StandardCharsets.UTF_8);
    }

    @Override
    public byte[] symDecryptDefault(byte[] cypheredTextBytes, Key key) {
        return DecryptionUtils.aesSymmetricDecrypt(cypheredTextBytes, key);
    }
}
