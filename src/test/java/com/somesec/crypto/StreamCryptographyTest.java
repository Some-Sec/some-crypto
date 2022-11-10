package com.somesec.crypto;

import com.somesec.crypto.config.ConfigurationResolverImpl;
import com.somesec.crypto.decrypt.AESDecryption;
import com.somesec.crypto.decrypt.DecryptionOperation;
import com.somesec.crypto.encrypt.AESEncryption;
import com.somesec.crypto.encrypt.EncryptionOperation;
import com.somesec.crypto.key.DefaultKeyOperationImpl;
import com.somesec.crypto.key.KeyOperation;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

public class StreamCryptographyTest {

    public static final int TEN_MEGABYTE = 1024 * 1024 * 10;
    final EncryptionOperation encryptionOperation;
    final DecryptionOperation decryptionOperation;
    final KeyOperation keyOperation;

    {
        final ConfigurationResolverImpl resolver = new ConfigurationResolverImpl();
        encryptionOperation = new AESEncryption(resolver);
        decryptionOperation = new AESDecryption(resolver);
        keyOperation = new DefaultKeyOperationImpl(resolver);
    }


    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void encryptStreamDecrypt() throws IOException, NoSuchAlgorithmException {
        final Key key = keyOperation.generateSecretKey();
        final Path plaintextTestFile = Files.createTempFile("plaintextTestFile", "txt");
        final Path ciphertextTestFile = Files.createTempFile("ciphertextTestFile", "txt");
        final File plain = plaintextTestFile.toFile();
        final File ciphered = ciphertextTestFile.toFile();
        plain.deleteOnExit();
        ciphered.deleteOnExit();
        Assertions.assertTrue(plain.exists());
        Assertions.assertTrue(ciphered.exists());
        SecureRandom random = SecureRandom.getInstanceStrong();
        final byte[] data = new byte[TEN_MEGABYTE];
        random.nextBytes(data);
        try (final FileOutputStream fileOutputStream = new FileOutputStream(plain)) {
            fileOutputStream.write(data);
        }
        Assertions.assertEquals(TEN_MEGABYTE, Files.size(plaintextTestFile));
        final byte[] plainTextFingerPrint = fingerPrintFile(plaintextTestFile);
        final String plainTextHash = Hex.toHexString(plainTextFingerPrint);
        encryptionOperation.encrypt(Files.newInputStream(plaintextTestFile), Files.newOutputStream(ciphertextTestFile), key);
        Assertions.assertTrue(TEN_MEGABYTE < Files.size(ciphertextTestFile));
        final byte[] cipheredFileHash = fingerPrintFile(ciphertextTestFile);
        final String ciphertextHash = Hex.toHexString(cipheredFileHash);
        Assertions.assertNotEquals(plainTextHash, ciphertextHash);
        final byte[] decryptedBytes = decryptionOperation.decrypt(Files.readAllBytes(ciphertextTestFile), key);
        final String decryptedFileHash = Hex.toHexString(fingerprint(decryptedBytes));
        Assertions.assertEquals(plainTextHash, decryptedFileHash);
        Assertions.assertTrue(plain.delete());
        Assertions.assertTrue(ciphered.delete());
    }

    @Test
    void encryptDecryptStream() throws IOException, NoSuchAlgorithmException {
        final Key key = keyOperation.generateSecretKey();
        SecureRandom random = SecureRandom.getInstanceStrong();
        final byte[] data = new byte[TEN_MEGABYTE];
        random.nextBytes(data);
        final byte[] plainTextFingerPrint = fingerprint(data);
        final String plainTextHash = Hex.toHexString(plainTextFingerPrint);
        final byte[] encryptedData = encryptionOperation.encrypt(data, key);
        final byte[] cipheredDataHash = fingerprint(encryptedData);
        final String ciphertextHash = Hex.toHexString(cipheredDataHash);
        Assertions.assertNotEquals(plainTextHash, ciphertextHash);
        try (final InputStream in = new ByteArrayInputStream(encryptedData); ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            decryptionOperation.decrypt(in, outputStream, key);
            final String decryptedFileHash = Hex.toHexString(fingerprint(outputStream.toByteArray()));
            Assertions.assertEquals(plainTextHash, decryptedFileHash);
        }
    }

    private byte[] fingerPrintFile(Path file) throws IOException {
        return fingerprint(Files.readAllBytes(file));
    }

    private byte[] fingerprint(byte[] data) {
        final Digest digest = new SHA256Digest();
        final byte[] fingerprint = new byte[digest.getDigestSize()];
        digest.update(data, 0, data.length);
        digest.doFinal(fingerprint, 0);
        return fingerprint;
    }


}
