package com.somesec.crypto.token;

import java.text.ParseException;

public interface TokenService {

    String createJWE(String payload, byte[] publicKey) throws Exception;

    String decryptJWE(String jwe, byte[] privateKey) throws Exception;
}
