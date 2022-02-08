package com.somesec.crypto.decrypt;

import com.somesec.crypto.config.ConfigurationResolver;
import com.somesec.crypto.config.DefaultConfig;
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

    private final ConfigurationResolver resolver;

    public AESDecryption(final ConfigurationResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    public byte[] decrypt(byte[] bytes, Key key) {
        try {
            Cipher cipher = Cipher.getInstance(resolver.getConfig(DefaultConfig.AES_CIPHER_NAME), BouncyCastleProvider.PROVIDER_NAME);
            ByteBuffer bb = ByteBuffer.wrap(bytes);
            byte[] iv = new byte[(int) resolver.getConfig(DefaultConfig.AES_GCM_NONCE_LENGTH)];
            bb.get(iv);
            byte[] cipherText = new byte[bb.remaining()];
            bb.get(cipherText);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec((int) resolver.getConfig(DefaultConfig.AES_GCM_TAG_LENGTH_BYTE) * (int) resolver.getConfig(DefaultConfig.BIT_IN_A_BYTE), iv));
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
        return resolver.getConfig(DefaultConfig.AES_ALGORITHM_NAME);
    }
}