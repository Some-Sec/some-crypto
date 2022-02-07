package com.somesec.crypto.constant;

public enum MessagesCode {
    ERROR_ALGO_NOT_SUPPORTED("Algorithm [%s] is currently not supported"),
    ERROR_KEY_NOT_NULLABLE("Key can not be null"),
    ERROR_KEY_TYPE_NOT_SUPPORTED("KeyType [%s] not supported"),
    ERROR_KEY_GEN("Error during [%s] KeyPair generation."),
    ERROR_KEY_GEN_ALGO("Algorithm [%s] is not supported."),
    ERROR_KEY_GEN_PARAMS_MISMATCH("Mismatched parameters for KeyGeneration :\nAlgorithm:%s\nParameters:%s"),
    ERROR_KEY_DERIVATION("Could not derive a new Key."),
    ERROR_KEY_DESERIALIZATION("Could not deserialize Key."),
    ERROR_KEY_DESERIALIZATION_NOT_SUPPORTED("Unsupported PrivateKey parameters for key."),
    ERROR_ENCRYPTION_ALGO("Could not encrypt with algorithm : %s"),
    ERROR_DECRYPTION_ALGO("Could not decrypt with algorithm : %s"),
    ERROR_JOSE_PROVIDER_CREATION("Could not create the expected JOSEProvider"),
    ERROR_JWE_CREATION("Could not create JWE token"),
    ERROR_JWE_DECRYPTION("Could not decrypt JWE token"),
    ERROR_JWS_PARSING_FAILED("Could not parse JWS"),
    ERROR_JWS_INTEGRITY_CHECK_FAILED("Integrity check (signature check) failed on token"),

    ERROR_JWS_SIGNING("Could not sign JWS"),

    ERROR_NO_CONFIGURATION_FOR_KEY("Could not find any configuration property associated to key: [%s]"),


    LOG_DESERIALIZE_KEY("Key not of expected type %s")

    ;

    private final String message;

    MessagesCode(String message) {
        this.message = message;
    }

    public String getMessage(String... args) {
        return String.format(this.message, (Object[]) args);
    }


}
