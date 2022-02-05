package com.somesec.crypto.exception;

import com.somesec.crypto.constant.MessagesCode;

public class CryptoOperationException extends RuntimeException {
    public CryptoOperationException(String message) {
        super(message);
    }

    public CryptoOperationException(MessagesCode message, String... args) {
        super(message.getMessage(args));
    }

    public CryptoOperationException(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptoOperationException(MessagesCode message, Throwable cause, String... args) {
        super(message.getMessage(args), cause);
    }

}
