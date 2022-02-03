package com.somesec.crypto.key;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.somesec.crypto.constant.CryptoAlgorithm;
import com.somesec.crypto.constant.CryptoOperation;
import com.somesec.crypto.constant.MessagesCode;
import com.somesec.crypto.exception.CryptoOperationException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

import com.somesec.crypto.constant.CryptoConstantsEnum;

public class DefaultKeyOperationImpl implements KeyOperation {

    @Override
    public Key deriveSecretKey(char[] passphrase, CryptoAlgorithm algorithm) throws Exception {
        if (algorithm.getCryptoOperation() != CryptoOperation.SYMMETRIC) {
            throw new CryptoOperationException(MessagesCode.ERROR_KEY_GEN_ALGO, algorithm.name());
        }
        final SecretKeyFactory factory = SecretKeyFactory.getInstance(CryptoConstantsEnum.KEY_DEFAULT_PBKDF2_FACTORY.getValue());
        final KeySpec spec = new PBEKeySpec(passphrase, CryptoConstantsEnum.KEY_DEFAULT_32_BYTE_SALT.getValue(), CryptoConstantsEnum.KEY_DEFAULT_PBKDF2_ITERATION.getValue(), CryptoConstantsEnum.KEY_DEFAULT_AES_KEY_SIZE.getValue());
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), CryptoConstantsEnum.KEY_DEFAULT_SYMMETRIC_KEY_ALGORITHM.getValue());

    }

    @Override
    public KeyPair generateKeyPair(CryptoAlgorithm algorithm) {
        if (algorithm.getCryptoOperation() != CryptoOperation.ASYMMETRIC) {
            throw new CryptoOperationException(MessagesCode.ERROR_KEY_GEN_ALGO, algorithm.name());
        }
        return KeyUtils.generateKeyPair(algorithm.name(), algorithm.getKeyGenParameters());
    }

    @Override
    public Key generateSecretKey() {
        KeyGenAesParameters defaultAesParams = new KeyGenAesParameters(CryptoConstantsEnum.KEY_DEFAULT_AES_KEY_SIZE.getValue());
        return KeyUtils.generateKey(CryptoConstantsEnum.KEY_DEFAULT_SYMMETRIC_KEY_ALGORITHM.getValue(), defaultAesParams);
    }


    @Override
    public PrivateKey deserializePrivateKey(String key) {
        return (PrivateKey) KeyUtils.deserializeAsymmetricPrivateKey(key);
    }

    @Override
    public PublicKey deserializePublicKey(String key) {
        return (PublicKey) KeyUtils.deserializeAsymmetricPublicKey(key);
    }

    @Override
    public String getKeyFingerprint(Key key) {
        Digest digest = new SHA256Digest();
        return KeyUtils.getKeyFingerprintHex(key, digest);
    }

    @Override
    public Key deserializeSecretKey(String secret) {
        return KeyUtils.deserializeAESKey(secret);
    }


}
