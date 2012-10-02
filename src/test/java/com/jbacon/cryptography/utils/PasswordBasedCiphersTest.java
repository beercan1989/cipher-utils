package com.jbacon.cryptography.utils;

import static org.junit.Assert.fail;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import com.jbacon.cryptography.CipherMode;

public class PasswordBasedCiphersTest {

    @BeforeClass
    public static void beforeClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void shouldBeAbleToEncryptWithPbeWithMD5AndDes() {
        fail("Not yet implemented");
    }

    @Test
    public void shouldBeAbleToRunTest() throws Exception {
        final byte[] salt = GenericCipherUtils.generateSalt(8);
        final char[] password = new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        final String test = PasswordBasedCipherUtils.PBE_SHA256_AES_CBC.test(CipherMode.ENCRYPT, password, salt,
                "HelloWorld.");
        System.out.println(test);
    }
}
