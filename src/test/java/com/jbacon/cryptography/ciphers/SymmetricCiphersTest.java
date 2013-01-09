package com.jbacon.cryptography.ciphers;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.io.UnsupportedEncodingException;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Test;

import com.jbacon.cryptography.ciphers.errors.UnsupportedCipherEngine;
import com.jbacon.cryptography.utils.CipherUtils;

public class SymmetricCiphersTest {

    private static final byte[] TO_ENCRYPT = new byte[] { 72, 101, 108, 108, 111, 87, 111, 114, 108, 100 };
    private static final byte[] TO_DECRYPT = new byte[] { 64, -32, -57, 114, 0, 55, -73, -29, -33, 106, -70, 41, 32,
            55, 92, -14 };
    private static final byte[] AES_KEY = new byte[] { -57, -92, -38, -41, -8, -26, -13, -121, -100, -31, -106, 43,
            -64, -41, -57, 22, -55, -82, -99, -5, -123, -9, -19, -106, 15, -65, -102, 16, -23, -88, -18, 26 };

    @Test
    public void shouldBeAbleToEncryptWithAES() throws DataLengthException, IllegalStateException,
            InvalidCipherTextException, UnsupportedCipherEngine {
        final byte[] encrypted = SymmetricCiphers.AES.encrypt(AES_KEY, TO_ENCRYPT);

        assertThat(encrypted, is(equalTo(TO_DECRYPT)));
    }

    @Test
    public void shouldBeAbleToDencryptWithAES() throws DataLengthException, IllegalStateException,
            InvalidCipherTextException, UnsupportedEncodingException, UnsupportedCipherEngine {
        final byte[] decrypted = SymmetricCiphers.AES.decrypt(AES_KEY, TO_DECRYPT);

        assertThat(decrypted, is(equalTo(TO_ENCRYPT)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldBeUnAbleToUse512BitKey() throws DataLengthException, IllegalStateException,
            InvalidCipherTextException, UnsupportedCipherEngine {
        final byte[] key = CipherUtils.generateBytes(512);
        final byte[] input = CipherUtils.stringToByte("512 bit key");

        SymmetricCiphers.AES.encrypt(key, input);
    }

}
