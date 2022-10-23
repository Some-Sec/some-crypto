package com.somesec.crypto.exception;

import com.somesec.crypto.constant.MessagesCode;

/**
 * Default Exception thrown in case of any CryptoOperation related error. This is a {@link RuntimeException}
 */
public class CryptoOperationException extends RuntimeException {

    /**
     * Instantiates a new {@link CryptoOperationException} with the given parameters
     * @param message
     */
    public CryptoOperationException(String message) {
        super(message);
    }

    /**
     * Instantiates a new {@link CryptoOperationException} with the given parameters
     * @param message
     * @param args
     */
    public CryptoOperationException(MessagesCode message, String... args) {
        super(message.getMessage(args));
    }

    /**
     * Instantiates a new {@link CryptoOperationException} with the given parameters
     * @param message
     * @param cause
     */
    public CryptoOperationException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Instantiates a new {@link CryptoOperationException} with the given parameters
     * @param message
     * @param cause
     * @param args
     */
    public CryptoOperationException(MessagesCode message, Throwable cause, String... args) {
        super(message.getMessage(args), cause);
    }

}
