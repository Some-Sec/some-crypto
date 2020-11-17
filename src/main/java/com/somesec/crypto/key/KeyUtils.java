package com.somesec.crypto.key;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import com.somesec.crypto.exception.CryptoOperationException;


/**
 * Key parsing and utility operations using BouncyCastle
 */
public class KeyUtils {

    private final static Logger LOGGER = LogManager.getLogger(KeyUtils.class);
    private final static String RSA = "RSA";
    private final static String ECDSA = "ECDSA";
    private final static String AES = "AES";

    public static Key generateKeyWithPBKDF2(String keyDerivationAlgorithm, String keyGeneratedAlgorithm, char[] passphrase, int iterationCount, int keyLength,
        byte[] salt)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(keyDerivationAlgorithm);
        KeySpec spec = new PBEKeySpec(passphrase, salt, iterationCount, keyLength);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), keyGeneratedAlgorithm);
    }

    /**
     * Asymmetric KeyPair generation util.
     *
     * @param algorithm the algorithm to use to generate the KeyPair
     * @param parameters the KeyGenParameters object containing the parameters needed for the provided algorithm
     * @return the generated KeyPair
     */
    public static KeyPair generateKeyPair(String algorithm, KeyGenParameters parameters) {
        try {
            switch (algorithm) {
                case RSA:
                    KeyGenRsaParameters rsaParameters = (KeyGenRsaParameters) parameters;
                    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA, BouncyCastleProvider.PROVIDER_NAME);
                    keyGen.initialize(rsaParameters.getKeySize());
                    return keyGen.generateKeyPair();
                case ECDSA:
                    KeyGenEcParameters ecParameters = (KeyGenEcParameters) parameters;
                    ECNamedCurveParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec(ecParameters.getNamedCurve());
                    KeyPairGenerator generator = KeyPairGenerator.getInstance(ECDSA,
                        BouncyCastleProvider.PROVIDER_NAME);
                    generator.initialize(ecParameterSpec, new SecureRandom());
                    return generator.generateKeyPair();
            }
        } catch (ClassCastException e) {
            throw CryptoOperationException.mismatchedParameters(algorithm, parameters, e);
        } catch (Exception e) {
            throw CryptoOperationException.keyGenerationException(algorithm, e);
        }
        throw new CryptoOperationException(String.format("Algorithm %s is not supported.", algorithm));
    }

    /**
     * Symmetric Key generation util.
     *
     * @param algorithm the algorithm to use to generate the Key
     * @param parameters the KeyGenParameters object containing the parameters needed for the provided algorithm
     * @return the generated Key
     */
    public static Key generateKey(String algorithm, KeyGenParameters parameters) {
        try {
            switch (algorithm) {
                case AES:
                    KeyGenAesParameters aesParameters = (KeyGenAesParameters) parameters;
                    SecureRandom random = SecureRandom.getInstanceStrong();
                    KeyGenerator keyGen = KeyGenerator.getInstance(AES, BouncyCastleProvider.PROVIDER_NAME);
                    keyGen.init(aesParameters.getKeySize(), random);
                    return keyGen.generateKey();
            }
        } catch (ClassCastException e) {
            throw CryptoOperationException.mismatchedParameters(algorithm, parameters, e);
        } catch (Exception e) {
            throw CryptoOperationException.keyGenerationException(algorithm, e);
        }
        throw new CryptoOperationException(String.format("Algorithm %s is not supported.", algorithm));
    }

    public static Key deserializeAsymmetricPrivateKey(String b64Key) {
        try {
            AsymmetricKeyParameter keyParams = PrivateKeyFactory.createKey(Base64.getDecoder().decode(b64Key));
            if (keyParams.isPrivate()) {
                PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(b64Key));
                if (keyParams instanceof ECKeyParameters) {
                    return KeyFactory.getInstance(ECDSA, BouncyCastleProvider.PROVIDER_NAME).generatePrivate(keySpecPKCS8);
                }
                if (keyParams instanceof RSAKeyParameters) {
                    return KeyFactory.getInstance(RSA, BouncyCastleProvider.PROVIDER_NAME).generatePrivate(keySpecPKCS8);
                }
                throw new Exception("Unsupported PrivateKey parameters for key\n" + b64Key);
            } else {
                X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(b64Key));
                if (keyParams instanceof ECKeyParameters) {
                    return KeyFactory.getInstance(ECDSA, BouncyCastleProvider.PROVIDER_NAME).generatePublic(keySpecX509);
                }
                if (keyParams instanceof RSAKeyParameters) {
                    return KeyFactory.getInstance(RSA, BouncyCastleProvider.PROVIDER_NAME).generatePublic(keySpecX509);
                }
                throw new Exception("Unsupported PublicKey parameters for key\n" + b64Key);
            }
        } catch (Exception ex) {
            throw CryptoOperationException.keyDeserializationException(b64Key, ex);
        }
    }

    public static Key deserializeAsymmetricPublicKey(String b64Key) {
        //Try to deserialize as RSA key
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(RSA, BouncyCastleProvider.PROVIDER_NAME);
            return keyFactory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(b64Key)));
        } catch (Exception ex) {
            LOGGER.info("Could not deserialize PublicKey as a RSA key. Trying ECDSA.");
            try {
                final KeyFactory keyFactory = KeyFactory.getInstance(ECDSA, BouncyCastleProvider.PROVIDER_NAME);
                return keyFactory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(b64Key)));
            } catch (Exception ex2) {
                LOGGER.error("Could not deserialize PublicKey as RSA.", ex);
                throw CryptoOperationException.keyDeserializationException(b64Key, ex2);
            }
        }
    }

    public static Key deserializeAESKey(String b64key) {
        return new SecretKeySpec(Base64.getDecoder().decode(b64key), AES);
    }

    public static String getKeyFingerprintHex(Key key, Digest digest) {
        byte[] fingerprint = getKeyFingerprint(key, digest);
        return Hex.toHexString(fingerprint);
    }

    public static byte[] getKeyFingerprint(Key key, Digest digest) {
        byte[] fingerprint = new byte[digest.getDigestSize()];
        byte[] encodedKey = key.getEncoded();
        digest.update(encodedKey, 0, encodedKey.length);
        digest.doFinal(fingerprint, 0);
        return fingerprint;
    }

    public static byte[] generateBytesFromHkdf(byte[] seed, byte[] info, byte[] salt, int length, Digest digest) {
        HKDFParameters params = new HKDFParameters(seed, salt, info);
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(digest);
        hkdf.init(params);
        byte[] generatedKey = new byte[length];
        hkdf.generateBytes(generatedKey, 0, length);
        return generatedKey;
    }
}
