package com.somesec.crypto.key;

import com.somesec.crypto.config.ConfigurationResolverImpl;
import com.somesec.crypto.constant.SupportedAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class KeyOperationTest {

    private final KeyOperation operation = new DefaultKeyOperationImpl(new ConfigurationResolverImpl());

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void deriveSecretKey() {

        final Key key = operation.deriveSecretKey("Hello There".toCharArray(), SupportedAlgorithm.AES);
        assertNotNull(key);
        assertInstanceOf(SecretKey.class, key);
        assertEquals(key.getAlgorithm(), SupportedAlgorithm.AES.name());


    }

    @Test
    void generateKeyPair() {
        final KeyPair rsaKeyPair = operation.generateKeyPair(SupportedAlgorithm.RSA);
        assertEquals(SupportedAlgorithm.RSA.name(), rsaKeyPair.getPublic().getAlgorithm());
        final KeyPair ecKeyPair = operation.generateKeyPair(SupportedAlgorithm.ECDSA);
        assertEquals(SupportedAlgorithm.ECDSA.name(), ecKeyPair.getPublic().getAlgorithm());
    }

    @Test
    void generateSecretKey() {

        final Key key = operation.generateSecretKey();
        assertInstanceOf(SecretKey.class, key);
        assertEquals(SupportedAlgorithm.AES.name(), key.getAlgorithm());
    }

    @Test
    void deserializeKeyPair() {
        //RSA
        final String rsaPrivateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCvWGQjeUZaomNoD2XU1RjgINV4W2+Bu4qUOfTWgxyRH7R0laeNN/+GazQXURRsIXCdJ+tfJR3pD0+l8aTI8K9XfOCOGYdx/ua0YkvuEhixbYr5yKY9s/oH7BgaNXLR3N+FsasssODljCKpqOSGXJfv5YpqHqZr0fv3lLCMJWnDvNY/EyD/DY9GwiD+U7lyVENWdrdB4fFYILop+4eL1nUNsZaoQGdm5+DyVb+ZpPDyYRBfHK6peEYMMoIty0vT+LcyfAYDMecGBdTMNxjT0RnAvPEKguomOCwozseDMFNAnM8fvmBrMW1PMEFeaJyvMaQYL62JLXtL7SHWDNH48JWpAgMBAAECggEACGpIUgiDtx1Ugn28sCBzA2yn+hD/Ur1WqwL2DGZ59EAOh8rX4ffmSEP0WcsfHQpkznIIQoZ0P0doFel5NFiSvbLlTwSMIs0uMsmF5dzR+Q/uC8tUqSDuVrt+s6FNi6NbSd4LPkeV34Zgcn6Dyyv98bo1MJ8ccw++lTT6XRt9jjJ5G3E/dim000KP6QNnoFPTYfzK0wFnR+FurjOUBeUZFusE12ToLBSmGHq9T8l9qdx+Ahgy/vWLVCQEahhsl056K1EVbJpLaQupl2iAPwPT7+TwR4+//F7b6EthPIr1iJUfG6eH90zm3P193TQ6F5NVSYbqzxw5ZOy5+hnCIKsXQQKBgQDyZnvrq7Ef1SkjVsAYbIafchtjKWy5+TWpIXNLSzEF0mrq++Jo4pKTfcSugi9BVpAUpNMlcBPgJJLftLvHWnCdMCZFsBAMFo+RDLm1QQxYMKJ51Mv5mo29oooka+rtrE5N2JFQaYjSFEuNVQHNYoYmzPqxTc9VIrZWd+6i1uIPiQKBgQC5LtFKK10Bi9CwsRglJQVwJDxVUAKXnV6jlxH5WZqCQXkxu+SXfsrw8TZkX9qoUNIc8vsLvqDpDcn0TdBH1r2uI9ken4rE6U+XjmcN8nCEyQb6dJFP4x1GPjZZo/E11tUc4NBD4zqCdG3sM7fks5OXbqMFYubJV0rycz2QDqWtIQKBgQDPj/4QwYX8EhUV05TN1TA5nAXjlXcqkEDowGHvWUVzDMjMyj8HPOvyK8GdBJDeS/c4FiNPbXc3eVnjAOnCPKktkCtVhPtYvoDU3aavlDGz2oFl/VdkNnmkpmfP5DDYr7ClbAqSZqvn58UCEoZmjjT9SIxqAozFA+JKjIvlGEeesQKBgFe4stHEquEhnzEkIwDtgZ72u1Hafe/eT0eFN7F73bJYW5XQoN+W44GxcgeoVIcpCe9Gtt+AZO8hZgqBlemB8wZ72s0j3HOc5eQwQ+cacmykYdbgwzkpp+NvcwWRoKDVbMyqPl36VOwZRTz/3tvKqV6xvS2/BP5ZiJpDNuV32smhAoGBAKQexwL0GYYHtf/xqMP0O5X9ym5VXsVF0nayc7YtPoYinN7OzY2PzoBUnL7imYLXa9xEKCz9ctNK0SBwLQxo7c+zuKTzRrlCPRXiCzlPweUibJOqweN0jq5z1+BE0ytGY04JGv2Loc8hI19AGhaBsqMOEDxlr2Es1OrlkJt5Hxzx";
        final String rsaPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr1hkI3lGWqJjaA9l1NUY4CDVeFtvgbuKlDn01oMckR+0dJWnjTf/hms0F1EUbCFwnSfrXyUd6Q9PpfGkyPCvV3zgjhmHcf7mtGJL7hIYsW2K+cimPbP6B+wYGjVy0dzfhbGrLLDg5YwiqajkhlyX7+WKah6ma9H795SwjCVpw7zWPxMg/w2PRsIg/lO5clRDVna3QeHxWCC6KfuHi9Z1DbGWqEBnZufg8lW/maTw8mEQXxyuqXhGDDKCLctL0/i3MnwGAzHnBgXUzDcY09EZwLzxCoLqJjgsKM7HgzBTQJzPH75gazFtTzBBXmicrzGkGC+tiS17S+0h1gzR+PCVqQIDAQAB";
        final PrivateKey rsaDeserializedPrivate = operation.deserializePrivateKey(Base64.getDecoder().decode(rsaPrivateKey));
        final PublicKey rsaDeserializedPublic = operation.deserializePublicKey(Base64.getDecoder().decode(rsaPublicKey));
        assertEquals(rsaPrivateKey, Base64.getEncoder().encodeToString(rsaDeserializedPrivate.getEncoded()));
        assertEquals(rsaPublicKey, Base64.getEncoder().encodeToString(rsaDeserializedPublic.getEncoded()));
        // ECDSA
        final String ecPrivateKey = "MHsCAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQEEYTBfAgEBBBgk6N4EFa23AAqPlUqW/3x2K85p2+Zu6emgCgYIKoZIzj0DAQGhNAMyAAQGUNuXS239z+I2dcOLlhJ76JDki0N7fBiziEc6nCLW6H+NBD0aKrLKoGMWRximOyU=";
        final String ecPublicKey = "MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEBlDbl0tt/c/iNnXDi5YSe+iQ5ItDe3wYs4hHOpwi1uh/jQQ9GiqyyqBjFkcYpjsl";
        final PrivateKey ecDeserializedPrivate = operation.deserializePrivateKey(Base64.getDecoder().decode(ecPrivateKey));
        final PublicKey ecDeserializedPublic = operation.deserializePublicKey(Base64.getDecoder().decode(ecPublicKey));
        assertEquals(ecPrivateKey, Base64.getEncoder().encodeToString(ecDeserializedPrivate.getEncoded()));
        assertEquals(ecPublicKey, Base64.getEncoder().encodeToString(ecDeserializedPublic.getEncoded()));

    }


    @Test
    void getKeyFingerprint() {
        final String aesKey = "D5SZyM4WOrrmp8CUnXID+u6Yr+GXT3xEVa50Pw+/rNs=";
        final String sha256 = "e7bebd8daaa8d104961215c126716f9a46d6add1a7205c388681729ba952d34c";
        final Key key = operation.deserializeSecretKey(Base64.getDecoder().decode(aesKey));
        final String fingerprint = operation.getKeyFingerprint(key);
        assertEquals(sha256,fingerprint);
    }

    @Test
    void deserializeSecretKey() {
        final String aesKey = "D5SZyM4WOrrmp8CUnXID+u6Yr+GXT3xEVa50Pw+/rNs=";
        final Key key = operation.deserializeSecretKey(Base64.getDecoder().decode(aesKey));
        assertEquals(aesKey, Base64.getEncoder().encodeToString(key.getEncoded()));
    }
}
