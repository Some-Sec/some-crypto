package com.somesec.crypto.constant;

/**
 * Interface declaring a specific algorithm, to see default supported algorithm see {@link SupportedAlgorithm} which implements this interface
 */
public interface CryptoAlgorithm {


    /**
     * Returns the cryptographic nature of this algorithm such as SYMMETRIC or ASYMMETRIC
     * @return SYMMETRIC or ASYMMETRIC
     */
    CryptographicType getCryptographicType();


    /**
     * The name of the algorithm such as AES, RSA, ECDSA...
     * @return string name of Algorithm
     */
    String name();

}
