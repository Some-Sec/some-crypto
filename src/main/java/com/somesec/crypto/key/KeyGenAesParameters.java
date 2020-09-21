package com.somesec.crypto.key;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.ToString;

@Data
@AllArgsConstructor
@ToString
public class KeyGenAesParameters implements KeyGenParameters {

    private int keySize;

}
