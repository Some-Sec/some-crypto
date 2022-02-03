package com.somesec.crypto.key;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

import com.somesec.crypto.constant.CryptoConstantsEnum;

public class KeyServiceDefaultImpl implements KeyService {

    @Override
    public Key getAesKeyForPassphrase(char[] passphrase) throws Exception {
        return KeyUtils.generateKeyWithPBKDF2(CryptoConstantsEnum.KEY_DEFAULT_PBKDF2_FACTORY.getValue(),
                CryptoConstantsEnum.KEY_DEFAULT_SYMMETRIC_KEY_ALGORITHM.getValue(), passphrase,
                CryptoConstantsEnum.KEY_DEFAULT_PBKDF2_ITERATION.getValue(), CryptoConstantsEnum.KEY_DEFAULT_AES_KEY_SIZE.getValue(),
                CryptoConstantsEnum.KEY_DEFAULT_32_BYTE_SALT.getValue());
    }

    @Override
    public KeyPair generateEcKeyPair() {
        KeyGenEcParameters defaultEcParams = new KeyGenEcParameters(CryptoConstantsEnum.KEY_DEFAULT_ECDSA_CURVE_NAME.getValue());
        return KeyUtils.generateKeyPair(CryptoConstantsEnum.ECDSA.getValue(), defaultEcParams);
    }

    @Override
    public KeyPair generateRSAKeyPair() {
        KeyGenRsaParameters defaultRsaParams = new KeyGenRsaParameters(CryptoConstantsEnum.KEY_DEFAULT_RSA_SIZE.getValue());
        return KeyUtils.generateKeyPair(CryptoConstantsEnum.RSA.getValue(), defaultRsaParams);
    }

    @Override
    public Key generateAesKey() {
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
    public Key generateAesKeyFromHkdf(byte[] inputData) {
        byte[] info = ((String) CryptoConstantsEnum.KEY_DEFAULT_HKDF_INFO.getValue()).getBytes(StandardCharsets.UTF_8);
        int keySize = CryptoConstantsEnum.KEY_DEFAULT_AES_KEY_SIZE.getValue();
        byte[] salt = CryptoConstantsEnum.KEY_DEFAULT_32_BYTE_SALT.getValue();
        Digest digest = CryptoConstantsEnum.KEY_HKDF_DEFAULT_DIGEST.getValue();
        return new SecretKeySpec(KeyUtils.generateBytesFromHkdf(inputData, info, salt, keySize, digest), CryptoConstantsEnum.AES.getValue());
    }

    @Override
    public Key deserializeAESKey(String secret) {
        return KeyUtils.deserializeAESKey(secret);
    }
}
