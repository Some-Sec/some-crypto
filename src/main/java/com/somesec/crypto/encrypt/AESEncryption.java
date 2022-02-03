package com.somesec.crypto.encrypt;

import com.somesec.crypto.constant.CryptoConstantsEnum;
import com.somesec.crypto.constant.CryptoOperation;
import com.somesec.crypto.constant.MessagesCode;
import com.somesec.crypto.exception.CryptoOperationException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.SecureRandom;

public final class AESEncryption implements EncryptionOperation {

    public byte[] encrypt(byte[] payload, Key key) {
        try {
            Cipher cipher = Cipher.getInstance(CryptoConstantsEnum.AES_CIPHER.getValue(), BouncyCastleProvider.PROVIDER_NAME);
            SecureRandom random = SecureRandom.getInstanceStrong();
            final byte[] nonce = new byte[(int) CryptoConstantsEnum.AES_DEFAULT_GCM_NONCE_LENGTH.getValue()];
            random.nextBytes(nonce);
            GCMParameterSpec spec = new GCMParameterSpec((int) CryptoConstantsEnum.AES_DEFAULT_GCM_TAG_LENGTH_BYTE.getValue() * ((int) CryptoConstantsEnum.BIT_IN_A_BYTE.getValue()), nonce);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            byte[] cipherText = cipher.doFinal(payload);
            return ByteBuffer.allocate((int) CryptoConstantsEnum.AES_DEFAULT_GCM_NONCE_LENGTH.getValue() + cipherText.length)
                    .put(nonce)
                    .put(cipherText)
                    .array();
        } catch (Exception ex) {
            throw new CryptoOperationException(MessagesCode.ERROR_ENCRYPTION_ALGO, ex, CryptoConstantsEnum.AES.getValue());
        }
    }


    @Override
    public CryptoOperation getSupportedOperation() {
        return CryptoOperation.SYMMETRIC;
    }

    @Override
    public Class<? extends Key> getKeyClass() {
        return SecretKey.class;
    }
}
