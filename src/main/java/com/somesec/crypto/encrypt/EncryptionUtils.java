package com.somesec.crypto.encrypt;

import java.nio.ByteBuffer;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.somesec.crypto.CryptoConstantsEnum;
import com.somesec.crypto.exception.CryptoOperationException;

public class EncryptionUtils {

    public static byte[] aesSymmetricEncrypt(byte[] data, Key encryptionKey) {
        try {
            Cipher cipher = Cipher.getInstance((String) CryptoConstantsEnum.AES.getValue(), BouncyCastleProvider.PROVIDER_NAME);
            SecureRandom random = SecureRandom.getInstanceStrong();
            final byte[] nonce = new byte[(Integer) CryptoConstantsEnum.AES_DEFAULT_GCM_NONCE_LENGTH.getValue()];
            random.nextBytes(nonce);
            GCMParameterSpec spec = new GCMParameterSpec((Integer) CryptoConstantsEnum.AES_DEFAULT_GCM_TAG_LENGTH.getValue() * 8, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, spec);
            byte[] cipherText = cipher.doFinal(data);
            return ByteBuffer.allocate((Integer) CryptoConstantsEnum.AES_DEFAULT_GCM_NONCE_LENGTH.getValue() + cipherText.length)
                .put(nonce)
                .put(cipherText)
                .array();
        } catch (Exception ex) {
            throw CryptoOperationException.encryptionException((String) CryptoConstantsEnum.AES.getValue(), ex);
        }
    }
}
