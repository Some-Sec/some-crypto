package com.somesec.crypto.key;

import com.somesec.crypto.config.ConfigurationResolver;
import com.somesec.crypto.config.DefaultConfig;
import com.somesec.crypto.constant.CryptoAlgorithm;
import com.somesec.crypto.constant.CryptographicType;
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

    private final ConfigurationResolver resolver;

    public DefaultKeyOperationImpl(final ConfigurationResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    public Key deriveSecretKey(char[] passphrase, CryptoAlgorithm algorithm) {
        if (algorithm.getCryptographicType() != CryptographicType.SYMMETRIC) {
            throw new CryptoOperationException(MessagesCode.ERROR_KEY_GEN_ALGO, algorithm.name());
        }
        if (algorithm == SupportedAlgorithm.AES) {
            try {
                final SecretKeyFactory factory = SecretKeyFactory.getInstance(resolver.getConfig(DefaultConfig.KEY_PBKDF2_FACTORY));
                final KeySpec spec = new PBEKeySpec(passphrase, resolver.getConfig(DefaultConfig.SALT), resolver.getConfig(DefaultConfig.PBKDF2_ITERATION), resolver.getConfig(DefaultConfig.SYMMETRIC_KEY_SIZE));
                return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), resolver.getConfig(DefaultConfig.SYMMETRIC_KEY_ALGORITHM));
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new CryptoOperationException(MessagesCode.ERROR_KEY_DERIVATION, e);
            }
        }
        throw new CryptoOperationException(MessagesCode.ERROR_KEY_GEN_ALGO, algorithm.name());

    }

    @Override
    public KeyPair generateKeyPair(CryptoAlgorithm algorithm) {
        if (algorithm.getCryptographicType() != CryptographicType.ASYMMETRIC) {
            throw new CryptoOperationException(MessagesCode.ERROR_KEY_GEN_ALGO, algorithm.name());
        }
        try {
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm.name(), BouncyCastleProvider.PROVIDER_NAME);
            if (algorithm == SupportedAlgorithm.RSA) {
                keyGen.initialize((int) resolver.getConfig(DefaultConfig.RSA_KEY_SIZE));
            } else if (algorithm == SupportedAlgorithm.ECDSA) {
                final ECNamedCurveParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec(resolver.getConfig(DefaultConfig.ECDSA_CURVE_NAME));
                keyGen.initialize(ecParameterSpec, SecureRandom.getInstanceStrong());
            } else {
                throw new CryptoOperationException(MessagesCode.ERROR_KEY_GEN_ALGO, algorithm.name());
            }
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new CryptoOperationException(MessagesCode.ERROR_KEY_GEN, e, algorithm.name());
        }


    }

    @Override
    public Key generateSecretKey() {
        try {
            byte[] seed = new byte[(int) resolver.getConfig(DefaultConfig.SYMMETRIC_KEY_SIZE)];
            final SecureRandom rnd = SecureRandom.getInstanceStrong();
            rnd.nextBytes(seed);
            final char[] passphrase = new char[seed.length];
            for (int i = 0; i < seed.length; i++) {
                passphrase[i]= ((char) seed[i]);
            }
            return this.deriveSecretKey(passphrase, SupportedAlgorithm.AES);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoOperationException(MessagesCode.ERROR_KEY_DERIVATION, e);
        }

    }


    @Override
    public PrivateKey deserializePrivateKey(String key) {
        final Base64.Decoder decoder = Base64.getDecoder();
        final byte[] keyEncoded = decoder.decode(key);
        return this.deserializePrivateKey(keyEncoded);
    }

    @Override
    public PrivateKey deserializePrivateKey(byte[] key) {
        try {
            final AsymmetricKeyParameter keyParams = PrivateKeyFactory.createKey(key);
            if (!keyParams.isPrivate()) {
                throw new CryptoOperationException(MessagesCode.ERROR_KEY_DESERIALIZATION);
            }
            final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
            final KeyFactory instance = getAsymmetricKeyFactory(keyParams);
            return instance.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | IOException | NoSuchProviderException | InvalidKeySpecException e) {
            throw new CryptoOperationException(MessagesCode.ERROR_KEY_DERIVATION, e);
        }
    }

    private KeyFactory getAsymmetricKeyFactory(AsymmetricKeyParameter keyParams) throws NoSuchAlgorithmException, NoSuchProviderException {
        final SupportedAlgorithm algorithm = determineAlgorithmFromAsymmetricKey(keyParams);
        return KeyFactory.getInstance(algorithm.name(), BouncyCastleProvider.PROVIDER_NAME);
    }

    private SupportedAlgorithm determineAlgorithmFromAsymmetricKey(final AsymmetricKeyParameter keyParams) {
        if (keyParams instanceof ECKeyParameters) {
            return SupportedAlgorithm.ECDSA;
        } else if (keyParams instanceof RSAKeyParameters) {
            return SupportedAlgorithm.RSA;
        }
        throw new CryptoOperationException(MessagesCode.ERROR_KEY_DESERIALIZATION_NOT_SUPPORTED);
    }

    @Override
    public PublicKey deserializePublicKey(String key) {
        final Base64.Decoder decoder = Base64.getDecoder();
        final byte[] encodedKey = decoder.decode(key);
        return this.deserializePublicKey(encodedKey);

    }

    @Override
    public PublicKey deserializePublicKey(byte[] key) {
        try {
            final AsymmetricKeyParameter keyParams = PublicKeyFactory.createKey(key);
            if (keyParams.isPrivate()) {
                throw new CryptoOperationException(MessagesCode.ERROR_KEY_DESERIALIZATION);
            }
            final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
            final KeyFactory instance = getAsymmetricKeyFactory(keyParams);
            return instance.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | IOException | NoSuchProviderException | InvalidKeySpecException e) {
            throw new CryptoOperationException(MessagesCode.ERROR_KEY_DESERIALIZATION, e);
        }
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

    @Override
    public Key deserializeSecretKey(byte[] secret) {
        return new SecretKeySpec(secret, SupportedAlgorithm.AES.name());
    }


}
