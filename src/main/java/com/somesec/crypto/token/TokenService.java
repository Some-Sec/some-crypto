package com.somesec.crypto.token;

public interface TokenService {

    String createJWE(String payload, byte[] publicKey);

    String decryptJWE(String jwe, byte[] privateKey);
}
