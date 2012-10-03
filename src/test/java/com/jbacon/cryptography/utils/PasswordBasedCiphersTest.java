package com.jbacon.cryptography.utils;

import static org.junit.Assert.fail;

import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.jbacon.cryptography.CipherMode;

public class PasswordBasedCiphersTest {

    private byte[] salt;
    private byte[] iv;

    @BeforeClass
    public static void beforeClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Before
    public void before() throws NoSuchAlgorithmException {
        salt = GenericCipherUtils.generateSalt(8);
        iv = GenericCipherUtils.generateSalt(16);
    }

    @Test
    public void shouldBeAbleToEncryptWithPbeWithMD5AndDes() {
        fail("Not yet implemented");
    }

    @Test
    public void shouldBeAbleToRunTest() throws Exception {
        final char[] password = new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        final byte[] toEncrypt = GenericCipherUtils.stringToByte("HelloWorld.");

        final PasswordBasedCipherUtils pbeCipher = PasswordBasedCipherUtils.PBE_SHA256_AES_CBC;
        final byte[] encrypted = pbeCipher.test(CipherMode.ENCRYPT, password, salt, iv, toEncrypt);

        System.out.println(GenericCipherUtils.bytesToBase64EncodedString(encrypted));
    }

    @Test
    public void shouldBeAbleToRunTest2() throws Exception {
        final char[] password = new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        final byte[] toEncrypt = GenericCipherUtils.stringToByte("HelloWorld.");

        final PasswordBasedCipherUtils pbeCipher = PasswordBasedCipherUtils.PBE_SHA256_AES_CBC;

        final byte[] encrypted = pbeCipher.test2(CipherMode.ENCRYPT, password, salt, iv, toEncrypt);
        System.out.println(GenericCipherUtils.bytesToBase64EncodedString(encrypted));

        final byte[] encrypted2 = pbeCipher.test(CipherMode.ENCRYPT, password, salt, iv, toEncrypt);
        System.out.println(GenericCipherUtils.bytesToBase64EncodedString(encrypted2));
    }
}
