package com.somesec.crypto.exception;

public class CryptoOperationException extends RuntimeException {
    public CryptoOperationException(String message) {
        super(message);
    }

    public CryptoOperationException(String message, Throwable cause) {
        super(message, cause);
    }

}
