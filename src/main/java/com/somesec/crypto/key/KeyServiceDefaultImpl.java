package com.somesec.crypto.key;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

import com.somesec.crypto.CryptoConstantsEnum;

public class KeyServiceDefaultImpl implements KeyService {

    @Override
    public Key getAesKeyForPassphrase(char[] passphrase) throws Exception {
        return KeyUtils.generateKeyWithPBKDF2((String) CryptoConstantsEnum.KEY_DEFAULT_PBKDF2_FACTORY.getValue(),
            (String) CryptoConstantsEnum.KEY_DEFAULT_SYMMETRIC_KEY_ALGORITHM.getValue(), passphrase,
            (Integer) CryptoConstantsEnum.KEY_DEFAULT_PBKDF2_ITERATION.getValue(), (Integer) CryptoConstantsEnum.KEY_DEFAULT_AES_KEY_SIZE.getValue(),
            (byte[]) CryptoConstantsEnum.KEY_DEFAULT_32_BYTE_SALT.getValue());
    }

    @Override
    public KeyPair generateEcKeyPair() {
        KeyGenEcParameters defaultEcParams = new KeyGenEcParameters((String) CryptoConstantsEnum.KEY_DEFAULT_ECDSA_CURVE_NAME.getValue());
        return KeyUtils.generateKeyPair((String) CryptoConstantsEnum.ECDSA.getValue(), defaultEcParams);
    }

    @Override
    public KeyPair generateRSAKeyPair() {
        KeyGenRsaParameters defaultRsaParams = new KeyGenRsaParameters((Integer) CryptoConstantsEnum.KEY_DEFAULT_RSA_SIZE.getValue());
        return KeyUtils.generateKeyPair((String) CryptoConstantsEnum.RSA.getValue(), defaultRsaParams);
    }

    @Override
    public Key generateAesKey() {
        KeyGenAesParameters defaultAesParams = new KeyGenAesParameters((Integer) CryptoConstantsEnum.KEY_DEFAULT_AES_KEY_SIZE.getValue());
        return KeyUtils.generateKey((String) CryptoConstantsEnum.KEY_DEFAULT_SYMMETRIC_KEY_ALGORITHM.getValue(), defaultAesParams);
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
    public Key generateAesKeyFromHkdf(byte[] inputData) {
        byte[] info = ((String) CryptoConstantsEnum.KEY_DEFAULT_HKDF_INFO.getValue()).getBytes(StandardCharsets.UTF_8);
        int keySize = (Integer) CryptoConstantsEnum.KEY_DEFAULT_AES_KEY_SIZE.getValue();
        byte[] salt = (byte[]) CryptoConstantsEnum.KEY_DEFAULT_32_BYTE_SALT.getValue();
        Digest digest = (Digest) CryptoConstantsEnum.KEY_HKDF_DEFAULT_DIGEST.getValue();
        return new SecretKeySpec(KeyUtils.generateBytesFromHkdf(inputData, info, salt, keySize, digest), (String) CryptoConstantsEnum.AES.getValue());
    }

    @Override
    public Key deserializeAESKey(String secret) {
        return KeyUtils.deserializeAESKey(secret);
    }
}
