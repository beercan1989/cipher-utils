package com.jbacon.cryptography.utils;

import static com.jbacon.cryptography.PBECiphers.PBE_MD5_AES_CBC;
import static com.jbacon.cryptography.PBECiphers.PBE_MD5_TWOFISH_CBC;
import static com.jbacon.cryptography.PBECiphers.PBE_SHA1_AES_CBC;
import static com.jbacon.cryptography.PBECiphers.PBE_SHA1_TWOFISH_CBC;
import static com.jbacon.cryptography.PBECiphers.PBE_SHA256_AES_CBC;
import static com.jbacon.cryptography.PBECiphers.PBE_SHA256_TWOFISH_CBC;
import static com.jbacon.cryptography.PBECiphers.PBE_SHA512_AES_CBC;
import static com.jbacon.cryptography.PBECiphers.PBE_SHA512_TWOFISH_CBC;
import static com.jbacon.cryptography.PBECiphers.PBE_WHIRLPOOL_AES_CBC;
import static com.jbacon.cryptography.PBECiphers.PBE_WHIRLPOOL_TWOFISH_CBC;
import static com.jbacon.cryptography.utils.CipherUtils.bytesToBase64Encoded;

import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

public class PBECiphersTest {

    private static final char[] password = new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
    private static final byte[] toEncrypt = CipherUtils.stringToByte("HelloWorld.");

    private static byte[] salt;
    private static byte[] iv;

    @BeforeClass
    public static void beforeClass() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());

        salt = CipherUtils.generateBytes(8);
        iv = CipherUtils.generateBytes(16);
    }

    @Test
    public void shouldBeAbleToRunDoCipher() throws Exception {
        System.out.println(bytesToBase64Encoded(PBE_MD5_AES_CBC.encrypt(password, salt, iv, toEncrypt)));
        System.out.println(bytesToBase64Encoded(PBE_SHA1_AES_CBC.encrypt(password, salt, iv, toEncrypt)));
        System.out.println(bytesToBase64Encoded(PBE_SHA256_AES_CBC.encrypt(password, salt, iv, toEncrypt)));
        System.out.println(bytesToBase64Encoded(PBE_SHA512_AES_CBC.encrypt(password, salt, iv, toEncrypt)));
        System.out.println(bytesToBase64Encoded(PBE_WHIRLPOOL_AES_CBC.encrypt(password, salt, iv, toEncrypt)));

        System.out.println();
        System.out.println(bytesToBase64Encoded(PBE_MD5_TWOFISH_CBC.encrypt(password, salt, iv, toEncrypt)));
        System.out.println(bytesToBase64Encoded(PBE_SHA1_TWOFISH_CBC.encrypt(password, salt, iv, toEncrypt)));
        System.out.println(bytesToBase64Encoded(PBE_SHA256_TWOFISH_CBC.encrypt(password, salt, iv, toEncrypt)));
        System.out.println(bytesToBase64Encoded(PBE_SHA512_TWOFISH_CBC.encrypt(password, salt, iv, toEncrypt)));
        System.out.println(bytesToBase64Encoded(PBE_WHIRLPOOL_TWOFISH_CBC.encrypt(password, salt, iv, toEncrypt)));
    }
}
