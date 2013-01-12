package co.uk.baconi.cryptography.ciphers;

import static co.uk.baconi.cryptography.utils.CipherUtils.base64EncodedStringToBytes;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.io.UnsupportedEncodingException;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Test;

import co.uk.baconi.cryptography.utils.CipherUtils;

public class SymmetricCiphersTest {

    private static final byte[] TO_ENCRYPT = base64EncodedStringToBytes("SGVsbG9Xb3JsZA==");
    private static final byte[] TO_DECRYPT = base64EncodedStringToBytes("QODHcgA3t+PfaropIDdc8g==");
    private static final byte[] AES_KEY = base64EncodedStringToBytes("x6Ta1/jm84ec4ZYrwNfHFsmunfuF9+2WD7+aEOmo7ho=");

    @Test
    public void shouldBeAbleToEncryptWithAES() throws DataLengthException, IllegalStateException, InvalidCipherTextException {
        final byte[] encrypted = SymmetricCiphers.AES.encrypt(AES_KEY, TO_ENCRYPT);

        assertThat(encrypted, is(equalTo(TO_DECRYPT)));
    }

    @Test
    public void shouldBeAbleToDencryptWithAES() throws DataLengthException, IllegalStateException, InvalidCipherTextException,
            UnsupportedEncodingException {
        final byte[] decrypted = SymmetricCiphers.AES.decrypt(AES_KEY, TO_DECRYPT);

        assertThat(decrypted, is(equalTo(TO_ENCRYPT)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldBeUnAbleToUse512BitKey() throws DataLengthException, IllegalStateException, InvalidCipherTextException {
        final byte[] key = CipherUtils.generateBytes(512);
        final byte[] input = CipherUtils.stringToByte("512 bit key");

        SymmetricCiphers.AES.encrypt(key, input);
    }

}
