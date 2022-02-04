package com.somesec.crypto.key;

import com.somesec.crypto.constant.CryptoAlgorithm;
import com.somesec.crypto.constant.CryptoConstantsEnum;
import com.somesec.crypto.constant.CryptoOperation;
import com.somesec.crypto.constant.MessagesCode;
import com.somesec.crypto.constant.SupportedAlgorithm;
import com.somesec.crypto.exception.CryptoOperationException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DefaultKeyOperationImpl implements KeyOperation {


    @Override
    public Key deriveSecretKey(char[] passphrase, CryptoAlgorithm algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (algorithm.getCryptoOperation() != CryptoOperation.SYMMETRIC) {
            throw new CryptoOperationException(MessagesCode.ERROR_KEY_GEN_ALGO, algorithm.name());
        }
        if (algorithm.getKeyGenParameters() instanceof KeyGenAesParameters) {
            final SecretKeyFactory factory = SecretKeyFactory.getInstance(CryptoConstantsEnum.KEY_DEFAULT_PBKDF2_FACTORY.getValue());
            final KeySpec spec = new PBEKeySpec(passphrase, CryptoConstantsEnum.KEY_DEFAULT_32_BYTE_SALT.getValue(), CryptoConstantsEnum.KEY_DEFAULT_PBKDF2_ITERATION.getValue(), CryptoConstantsEnum.KEY_DEFAULT_AES_KEY_SIZE.getValue());
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), CryptoConstantsEnum.KEY_DEFAULT_SYMMETRIC_KEY_ALGORITHM.getValue());
        }
        throw new CryptoOperationException(MessagesCode.ERROR_KEY_GEN_ALGO, algorithm.name());

    }

    @Override
    public KeyPair generateKeyPair(CryptoAlgorithm algorithm) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        if (algorithm.getCryptoOperation() != CryptoOperation.ASYMMETRIC) {
            throw new CryptoOperationException(MessagesCode.ERROR_KEY_GEN_ALGO, algorithm.name());
        }
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm.name(), BouncyCastleProvider.PROVIDER_NAME);
        if (algorithm == SupportedAlgorithm.RSA) {
            keyGen.initialize(((KeyGenRsaParameters) algorithm.getKeyGenParameters()).getKeySize());
        } else if (algorithm == SupportedAlgorithm.ECDSA) {
            final String curve = ((KeyGenEcParameters) algorithm.getKeyGenParameters()).getNamedCurve();
            final ECNamedCurveParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec(curve);
            keyGen.initialize(ecParameterSpec, SecureRandom.getInstanceStrong());
        } else {
            throw new CryptoOperationException(MessagesCode.ERROR_KEY_GEN_ALGO, algorithm.name());
        }
        return keyGen.generateKeyPair();

    }

    @Override
    public Key generateSecretKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] seed = new byte[(int) CryptoConstantsEnum.KEY_DEFAULT_AES_KEY_SIZE.getValue()];
        final SecureRandom rnd = SecureRandom.getInstanceStrong();
        rnd.nextBytes(seed);
        return this.deriveSecretKey(new String(seed, StandardCharsets.UTF_8).toCharArray(), SupportedAlgorithm.AES);
    }


    @Override
    public PrivateKey deserializePrivateKey(String key) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {

        final Base64.Decoder decoder = Base64.getDecoder();
        final AsymmetricKeyParameter keyParams = PrivateKeyFactory.createKey(decoder.decode(key));
        if (!keyParams.isPrivate()) {
            throw new CryptoOperationException(MessagesCode.ERROR_KEY_DESERIALIZATION, key);
        }
        final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoder.decode(key));
        final KeyFactory instance = getAsymmetricKeyFactory(key, keyParams);
        return instance.generatePrivate(keySpec);


    }

    private KeyFactory getAsymmetricKeyFactory(String key, AsymmetricKeyParameter keyParams) throws NoSuchAlgorithmException, NoSuchProviderException {
        SupportedAlgorithm algorithm;
        if (keyParams instanceof ECKeyParameters) {
            algorithm = SupportedAlgorithm.ECDSA;
        } else if (keyParams instanceof RSAKeyParameters) {
            algorithm = SupportedAlgorithm.RSA;
        } else {
            throw new CryptoOperationException(MessagesCode.ERROR_KEY_DESERIALIZATION_NOT_SUPPORTED, key);
        }
        return KeyFactory.getInstance(algorithm.name(), BouncyCastleProvider.PROVIDER_NAME);
    }

    @Override
    public PublicKey deserializePublicKey(String key) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {

        final Base64.Decoder decoder = Base64.getDecoder();
        final AsymmetricKeyParameter keyParams = PublicKeyFactory.createKey(decoder.decode(key));
        if (keyParams.isPrivate()) {
            throw new CryptoOperationException(MessagesCode.ERROR_KEY_DESERIALIZATION, key);
        }
        final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoder.decode(key));
        final KeyFactory instance = getAsymmetricKeyFactory(key, keyParams);
        return instance.generatePublic(keySpec);


    }

    @Override
    public String getKeyFingerprint(Key key) {
        final Digest digest = new SHA256Digest();
        final byte[] fingerprint = new byte[digest.getDigestSize()];
        final byte[] encodedKey = key.getEncoded();
        digest.update(encodedKey, 0, encodedKey.length);
        digest.doFinal(fingerprint, 0);
        return Hex.toHexString(fingerprint);
    }

    @Override
    public Key deserializeSecretKey(String secret) {
        return new SecretKeySpec(Base64.getDecoder().decode(secret), SupportedAlgorithm.AES.name());

    }


}
