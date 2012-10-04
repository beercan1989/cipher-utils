package com.jbacon.cryptography.utils;

import static com.jbacon.cryptography.utils.CipherUtils.bytesToBase64EncodedString;
import static com.jbacon.cryptography.utils.PasswordBasedCipherUtils.PBE_SHA1_AES_CBC;
import static com.jbacon.cryptography.utils.PasswordBasedCipherUtils.PBE_SHA1_TWOFISH_CBC;
import static com.jbacon.cryptography.utils.PasswordBasedCipherUtils.PBE_SHA256_AES_CBC;
import static com.jbacon.cryptography.utils.PasswordBasedCipherUtils.PBE_SHA256_TWOFISH_CBC;
import static com.jbacon.cryptography.utils.PasswordBasedCipherUtils.PBE_SHA512_AES_CBC;
import static com.jbacon.cryptography.utils.PasswordBasedCipherUtils.PBE_SHA512_TWOFISH_CBC;

import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import com.jbacon.cryptography.CipherMode;

public class PasswordBasedCiphersTest {

    private static final char[] password = new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
    private static final byte[] toEncrypt = CipherUtils.stringToByte("HelloWorld.");

    private static byte[] salt;
    private static byte[] iv;

    @BeforeClass
    public static void beforeClass() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());

        salt = CipherUtils.generateSalt(8);
        iv = CipherUtils.generateSalt(16);
    }

    @Test
    public void shouldBeAbleToRunDoCipher() throws Exception {
        System.out.println(bytesToBase64EncodedString(PBE_SHA1_AES_CBC.doCipher(CipherMode.ENCRYPT, password, salt, iv, toEncrypt)));
        System.out.println(bytesToBase64EncodedString(PBE_SHA256_AES_CBC.doCipher(CipherMode.ENCRYPT, password, salt, iv, toEncrypt)));
        System.out.println(bytesToBase64EncodedString(PBE_SHA512_AES_CBC.doCipher(CipherMode.ENCRYPT, password, salt, iv, toEncrypt)));

        System.out.println();
        System.out.println(bytesToBase64EncodedString(PBE_SHA1_TWOFISH_CBC.doCipher(CipherMode.ENCRYPT, password, salt, iv, toEncrypt)));
        System.out.println(bytesToBase64EncodedString(PBE_SHA256_TWOFISH_CBC.doCipher(CipherMode.ENCRYPT, password, salt, iv, toEncrypt)));
        System.out.println(bytesToBase64EncodedString(PBE_SHA512_TWOFISH_CBC.doCipher(CipherMode.ENCRYPT, password, salt, iv, toEncrypt)));
    }
}
