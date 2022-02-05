package com.somesec.crypto.encrypt;

import com.somesec.crypto.CryptographicOperation;

import java.security.Key;

public interface EncryptionOperation extends CryptographicOperation {

    byte[] encrypt(byte[] payload, Key key);

}
