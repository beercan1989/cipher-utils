package com.jbacon.cryptography.utils;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.io.UnsupportedEncodingException;

import org.apache.commons.lang.ArrayUtils;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Test;

import com.jbacon.cryptography.CipherMode;
import com.jbacon.cryptography.utils.SymmetricCipherUtils;


public class SymmetricCiphersTest {

    private static final byte[] TO_ENCRYPT = new byte[] { 72, 101, 108, 108, 111, 87, 111, 114, 108, 100 };
    private static final byte[] TO_DECRYPT = new byte[] { 64, -32, -57, 114, 0, 55, -73, -29, -33, 106, -70, 41, 32,
            55, 92, -14 };
    private static final byte[] AES_KEY = new byte[] { -57, -92, -38, -41, -8, -26, -13, -121, -100, -31, -106, 43,
            -64, -41, -57, 22, -55, -82, -99, -5, -123, -9, -19, -106, 15, -65, -102, 16, -23, -88, -18, 26 };

    @Test
    public void shouldBeAbleToEncryptWithAES() throws DataLengthException, IllegalStateException,
            InvalidCipherTextException {
        final SymmetricCipherUtils aesCipher = SymmetricCipherUtils.AES;

        final byte[] encrypted = aesCipher.doCipher(CipherMode.ENCRYPT, AES_KEY, TO_ENCRYPT);

        assertThat(encrypted, is(equalTo(TO_DECRYPT)));
    }

    @Test
    public void shouldBeAbleToDencryptWithAES() throws DataLengthException, IllegalStateException,
            InvalidCipherTextException, UnsupportedEncodingException {
        final SymmetricCipherUtils aesCipher = SymmetricCipherUtils.AES;

        final byte[] decrypted = aesCipher.doCipher(CipherMode.DECRYPT, AES_KEY, TO_DECRYPT);

        assertThat(decrypted, is(equalTo(ArrayUtils.addAll(TO_ENCRYPT, new byte[] { 0, 0, 0, 0, 0, 0 }))));
    }

}
