package com.somesec.crypto.decrypt;

import java.nio.ByteBuffer;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.somesec.crypto.CryptoConstantsEnum;
import com.somesec.crypto.exception.CryptoOperationException;

public class DecryptionUtils {

    public static byte[] aesSymmetricDecrypt(byte[] bytes, Key key) {
        try {
            Cipher cipher = Cipher.getInstance((String) CryptoConstantsEnum.AES.getValue(), BouncyCastleProvider.PROVIDER_NAME);
            ByteBuffer bb = ByteBuffer.wrap(bytes);
            byte[] iv = new byte[(Integer) CryptoConstantsEnum.AES_DEFAULT_GCM_NONCE_LENGTH.getValue()];
            bb.get(iv);
            byte[] cipherText = new byte[bb.remaining()];
            bb.get(cipherText);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec((Integer) CryptoConstantsEnum.AES_DEFAULT_GCM_TAG_LENGTH.getValue() * 8, iv));
            return cipher.doFinal(cipherText);
        } catch (Exception ex) {
            throw CryptoOperationException.decryptionException((String) CryptoConstantsEnum.AES.getValue(), ex);
        }
    }
}
