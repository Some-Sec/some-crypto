package com.somesec.crypto.exception;

import com.somesec.crypto.key.KeyGenParameters;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CryptoOperationException extends RuntimeException {

    public CryptoOperationException(String message) {
        super(message);
    }

    public CryptoOperationException(String message, Throwable cause) {
        super(message, cause);
    }

    public static CryptoOperationException keyGenerationException(String keyType, Throwable cause) {
        return new CryptoOperationException(String.format("Error during %s KeyPair generation.", keyType), cause);
    }

    public static CryptoOperationException mismatchedParameters(String algorithm, KeyGenParameters parameters, Throwable cause) {
        return new CryptoOperationException(
            String.format("Mismatched parameters for KeyGeneration :\nAlgorithm:%s\nParameters:%s", algorithm, parameters.toString()), cause);
    }

    public static CryptoOperationException keyDeserializationException(String key, Throwable cause) {
        return new CryptoOperationException(String.format("Could not deserialize Key :\n%s", key), cause);
    }

    public static CryptoOperationException encryptionException(String algorithm, Throwable cause) {
        return new CryptoOperationException(String.format("Could not encrypt with algorithm : %s", algorithm), cause);
    }

    public static CryptoOperationException decryptionException(String algorithm, Throwable cause) {
        return new CryptoOperationException(String.format("Could not decrypt with algorithm : %s", algorithm), cause);
    }

    public static CryptoOperationException jweTokenCreationException(Throwable cause) {
        return new CryptoOperationException("Could not create JWE token", cause);
    }

    public static CryptoOperationException jweTokenDecryptionException(Throwable cause) {
        return new CryptoOperationException("Could not decrypt JWE token", cause);
    }
}
