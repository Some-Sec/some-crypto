package com.somesec.crypto.decrypt;

import com.somesec.crypto.constant.CryptoConstants;
import com.somesec.crypto.constant.CryptographicType;
import com.somesec.crypto.constant.MessagesCode;
import com.somesec.crypto.exception.CryptoOperationException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.Key;

public final class AESDecryption implements DecryptionOperation {
    @Override
    public byte[] decrypt(byte[] bytes, Key key) {
        try {
            Cipher cipher = Cipher.getInstance(CryptoConstants.AES_CIPHER.getValue(), BouncyCastleProvider.PROVIDER_NAME);
            ByteBuffer bb = ByteBuffer.wrap(bytes);
            byte[] iv = new byte[(int) CryptoConstants.AES_DEFAULT_GCM_NONCE_LENGTH.getValue()];
            bb.get(iv);
            byte[] cipherText = new byte[bb.remaining()];
            bb.get(cipherText);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec((int) CryptoConstants.AES_DEFAULT_GCM_TAG_LENGTH_BYTE.getValue() * (int) CryptoConstants.BIT_IN_A_BYTE.getValue(), iv));
            return cipher.doFinal(cipherText);
        } catch (Exception ex) {
            throw new CryptoOperationException(MessagesCode.ERROR_DECRYPTION_ALGO, ex, getAlgorithmName());
        }
    }

    @Override
    public CryptographicType getSupportedOperation() {
        return CryptographicType.SYMMETRIC;
    }

    @Override
    public Class<? extends Key> getKeyClass() {
        return SecretKey.class;
    }

    @Override
    public String getAlgorithmName() {
        return CryptoConstants.AES.getValue();
    }
}
