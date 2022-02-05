package com.somesec.crypto.token;

public interface TokenService {

    String createJWE(String payload, byte[] publicKey) throws Exception;

    String decryptJWE(String jwe, byte[] privateKey) throws Exception;
}
