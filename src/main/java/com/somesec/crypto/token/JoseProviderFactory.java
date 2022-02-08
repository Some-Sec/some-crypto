package com.somesec.crypto.token;

import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;

import java.security.Key;

public interface JoseProviderFactory {


    JWEEncrypter getEncrypter(Key key);

    JWEDecrypter getDecrypter(Key key);

    JWSSigner getSigner(Key key);

    JWSVerifier getVerifier(Key key);

    JWEHeader.Builder getJWEHeaderBuilder(Key key);
    JWSHeader.Builder getJWSHeaderBuilder(Key key);


}
