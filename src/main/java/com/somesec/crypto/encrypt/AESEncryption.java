package com.somesec.crypto.encrypt;

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
import java.security.SecureRandom;
/**
 * Concrete implementation of a {@link EncryptionOperation} encrypts plain text with the {@link DefaultConfig#AES_CIPHER_NAME}
 */
public final class AESEncryption implements EncryptionOperation {

    private final ConfigurationResolver resolver;

    /**
     * Creates a new {@link AESEncryption} instance with the passed {@link ConfigurationResolver}
     * @param resolver
     */
    public AESEncryption(final ConfigurationResolver resolver) {
        this.resolver = resolver;
    }

    public byte[] encrypt(byte[] payload, Key key) {
        try {
            Cipher cipher = Cipher.getInstance(resolver.getConfig(DefaultConfig.AES_CIPHER_NAME), BouncyCastleProvider.PROVIDER_NAME);
            SecureRandom random = SecureRandom.getInstanceStrong();
            final byte[] nonce = new byte[(int) resolver.getConfig(DefaultConfig.AES_GCM_NONCE_LENGTH)];
            random.nextBytes(nonce);
            GCMParameterSpec spec = new GCMParameterSpec((int) resolver.getConfig(DefaultConfig.AES_GCM_TAG_LENGTH_BYTE) * ((int) resolver.getConfig(DefaultConfig.BIT_IN_A_BYTE)), nonce);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            byte[] cipherText = cipher.doFinal(payload);
            return ByteBuffer.allocate((int) resolver.getConfig(DefaultConfig.AES_GCM_NONCE_LENGTH) + cipherText.length)
                    .put(nonce)
                    .put(cipherText)
                    .array();
        } catch (Exception ex) {
            throw new CryptoOperationException(MessagesCode.ERROR_ENCRYPTION_ALGO, ex, getAlgorithmName());
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
