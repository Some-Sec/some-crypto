package com.somesec.crypto.decrypt;

import com.somesec.crypto.CryptographicOperation;

import java.security.Key;

public interface DecryptionOperation extends CryptographicOperation {
    byte[] decrypt(byte[] cypheredBytes, Key key);


}
