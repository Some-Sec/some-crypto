package com.somesec.crypto.key;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.somesec.crypto.constant.*;
import com.somesec.crypto.exception.CryptoOperationException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.encoders.Hex;

public class DefaultKeyOperationImpl implements KeyOperation {

    public static final int KEYGEN_SEED = 256;

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
        byte[] seed = new byte[KEYGEN_SEED];
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
        final AsymmetricKeyParameter keyParams = PrivateKeyFactory.createKey(decoder.decode(key));
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
