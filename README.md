# some-crypto

## The SomeSec's teams idea of an easy to use somewhat sane crypto library

This cryptographic library is a wrapper around popular crypto implementations BouncyCastle and Nimbus Jose

Although written and maintained carefully there is absolutely no guaranty that any of the implementation is free from
vulnerabilities

## How to get going

- Clone the repository
  `https://github.com/Some-Sec/some-crypto.git`
- build the project `mvn clean install`

- embed the library as a dependency into your `pom.xml`

```
  <dependency>
        <groupId>com.some-sec.libs</groupId>
        <artifactId>some-crypto</artifactId>
        <version>1.0.7</version>
  </dependency>
```

- implement PropertySource interface to pass in your configuration values for more detail go to [How to configure]()

## What is currently implemented

- Key derivation based on passphrase
- Random Key generation
- Key Pair generation RSA and ECDSA  
- Key Deserialization
- AES Encryption/Decryption based on AES GCM
- JWE based envelope encryption/Decryption with RSA


## How to configure

This library comes with below specified default values. Every singe lone can be overwritten by you.
to do this you MUST implement the PropertySource interface.

What ever your concrete implementation, the value you want to pass in must be associated with the key listed below.

If no value is specified, default values will be used. these can be found in the list below.

If you implement your own property source the values looked up from there will take precedence over default values.

``` 
    RSA_ALGORITHM_NAME("RSA"),
    ECDSA_ALGORITHM_NAME("ECDSA"),
    AES_ALGORITHM_NAME("AES"),
    AES_CIPHER_NAME("AES/GCM/NoPadding"),
    AES_GCM_NONCE_LENGTH(12),
    AES_GCM_TAG_LENGTH_BYTE(16),
    KEY_PBKDF2_FACTORY("PBKDF2WithHmacSHA256"),
    SYMMETRIC_KEY_ALGORITHM(AES_ALGORITHM_NAME.value),
    PBKDF2_ITERATION(65536),
    SYMMETRIC_KEY_SIZE(256),
    SALT(SOME-SALT-OVERRIDE-IN-PROD),
    ECDSA_CURVE_NAME("prime192v1"),
    RSA_KEY_SIZE(2048),
    BIT_IN_A_BYTE(8),

```

---
