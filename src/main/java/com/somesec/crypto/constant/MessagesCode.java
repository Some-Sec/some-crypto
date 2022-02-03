package com.somesec.crypto.constant;

public enum MessagesCode {

    ERROR_KEY_GEN("Error during %s KeyPair generation."),
    ERROR_KEY_GEN_ALGO("Algorithm %s is not supported."),
    ERROR_KEY_GEN_PARAMS_MISMATCH("Mismatched parameters for KeyGeneration :\nAlgorithm:%s\nParameters:%s"),
    ERROR_KEY_DESERIALIZATION("Could not deserialize Key :\n%s"),
    ERROR_KEY_DESERIALIZATION_NOT_SUPPORTED("Unsupported PrivateKey parameters for key\n%s"),
    ERROR_ENCRYPTION_ALGO("Could not encrypt with algorithm : %s"),
    ERROR_DECRYPTION_ALGO("Could not decrypt with algorithm : %s"),
    ERROR_JWE_CREATION("Could not create JWE token"),
    ERROR_JWE_DECRYPTION("Could not decrypt JWE token"),


    ;

    private final String message;

    MessagesCode(String message) {
        this.message = message;
    }

    public String getMessage(String... args) {
        return String.format(this.message, (Object[]) args);
    }


}
